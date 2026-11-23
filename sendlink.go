package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Sender takeover: the web SEND page hands its transfer to the CLI
// ("アプリで高速送信") with
//
//	beamdrop://HOST/s/ROOM?n=NAME&z=SIZE&m=MTIME_MS&c=CHUNK&h=HEAD&t=TAIL#k=KEY[&relay=1]
//
// A browser cannot tell us where the file lives, only what it is: NAME is
// the percent-encoded base name, HEAD/TAIL are hex SHA-256 of the first and
// last min(1MiB, SIZE) bytes. We find the file ourselves, the user confirms,
// and we send it into the room the page left - same key, same share link.
//
// This link makes the CLI SEND A LOCAL FILE and it comes from a web page, so
// it is treated as hostile: strict shape, trusted HOST only, NAME is only
// ever compared against directory entries (never joined into a path), the
// content must match both hashes, and nothing is sent without an explicit y.
var beamdropSendLinkRe = regexp.MustCompile(
	`^beamdrop://([A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?)/s/([A-Za-z0-9_-]{1,64})` +
		`\?n=([A-Za-z0-9._%-]{1,765})&z=([0-9]{1,15})&m=([0-9]{1,16})&c=([0-9]{4,5})` +
		`&h=([0-9a-f]{64})&t=([0-9a-f]{64})#k=([A-Za-z0-9_-]{16,128})(&relay=1)?$`)

const sendLinkHashSpan = 1 << 20

type sendLink struct {
	server   string
	room     string
	key      []byte
	relay    bool
	name     string
	size     int64
	chunk    int64
	headHash string
	tailHash string
}

func parseSendLink(link string) (sendLink, error) {
	var sl sendLink
	m := beamdropSendLinkRe.FindStringSubmatch(link)
	if m == nil {
		return sl, fmt.Errorf("not a valid beamdrop:// send link")
	}
	if !linkAllowedHosts()[m[1]] {
		return sl, fmt.Errorf("link points at %q, which is not a trusted beamdrop server (set BEAMDROP_LINK_HOSTS to allow it)", m[1])
	}
	name, err := url.PathUnescape(m[3])
	if err != nil || !utf8.ValidString(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return sl, fmt.Errorf("link carries an invalid file name")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return sl, fmt.Errorf("link carries an invalid file name")
		}
	}
	size, _ := strconv.ParseInt(m[4], 10, 64)
	chunk, _ := strconv.ParseInt(m[6], 10, 64)
	if chunk < 4096 || chunk > 48*1024 {
		return sl, fmt.Errorf("link carries an invalid chunk size")
	}
	key, err := b64URL.DecodeString(m[9])
	if err != nil || len(key) != 32 {
		return sl, fmt.Errorf("link carries an invalid key")
	}
	// m[5] (mtime) is only a hint and is not needed: content hashes decide.
	return sendLink{
		server: linkServerURL(m[1]), room: m[2], key: key, relay: m[10] != "",
		name: name, size: size, chunk: chunk, headHash: m[7], tailHash: m[8],
	}, nil
}

// checkSendCandidate reports why path is not the file the page was sending
// (nil = it is): regular file, same size, same first and last 1MiB.
func checkSendCandidate(path string, sl sendLink) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if st.Size() != sl.size {
		return fmt.Errorf("size is %d bytes, the browser's file is %d bytes", st.Size(), sl.size)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n := int64(sendLinkHashSpan)
	if sl.size < n {
		n = sl.size
	}
	for _, part := range []struct {
		off  int64
		want string
	}{{0, sl.headHash}, {sl.size - n, sl.tailHash}} {
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, part.off, n)); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != part.want {
			return fmt.Errorf("content differs from the file selected in the browser")
		}
	}
	return nil
}

// locateSendFile looks for the file in the places a browser upload usually
// comes from: the current directory, Downloads, Desktop, Documents, then the
// rest of the home directory. Bounded in depth and time; the first candidate
// whose name, size and hashes all match wins.
func locateSendFile(sl sendLink) string {
	home, _ := os.UserHomeDir()
	// macOS: ask Spotlight first. It knows every file under the home
	// directory by name instantly, however deep - the directory walk below
	// gave up on a file 8 folders down (~/work/.../data/speclib/x.json).
	if runtime.GOOS == "darwin" && home != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		q := `kMDItemFSName == "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(sl.name) + `"`
		out, err := exec.CommandContext(ctx, "mdfind", "-onlyin", home, q).Output()
		cancel()
		if err == nil {
			for _, p := range strings.Split(string(out), "\n") {
				if p = strings.TrimSpace(p); p == "" || !strings.HasPrefix(p, home+string(filepath.Separator)) {
					continue
				}
				if checkSendCandidate(p, sl) == nil {
					return p
				}
			}
		}
	}
	deadline := time.Now().Add(6 * time.Second)
	done := map[string]bool{}
	search := func(root string, maxDepth int) string {
		root = filepath.Clean(root)
		if done[root] || !isDir(root) {
			return ""
		}
		base := strings.Count(root, string(filepath.Separator))
		found := ""
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if time.Now().After(deadline) {
				return filepath.SkipAll
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p == root {
					return nil
				}
				n := d.Name()
				if strings.HasPrefix(n, ".") || n == "Library" || n == "AppData" || n == "node_modules" ||
					done[p] || strings.Count(p, string(filepath.Separator))-base > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			// WalkDir does not follow symlinks, so nothing outside root is
			// reached, and only regular files are considered.
			if d.Name() != sl.name || !d.Type().IsRegular() {
				return nil
			}
			if checkSendCandidate(p, sl) == nil {
				found = p
				return filepath.SkipAll
			}
			return nil
		})
		done[root] = true
		return found
	}
	if cwd, err := os.Getwd(); err == nil && cwd != home && filepath.Dir(cwd) != cwd {
		if p := search(cwd, 1); p != "" {
			return p
		}
	}
	if home == "" {
		return ""
	}
	for _, d := range []string{"Downloads", "Desktop", "Documents"} {
		if p := search(filepath.Join(home, d), 3); p != "" {
			return p
		}
	}
	// The time budget is the real bound; the depth cap only stops runaway
	// trees. 5 was too shallow for ordinary project folders.
	return search(home, 12)
}

// cleanPastedPath undoes what a terminal does to a dragged-in file: wraps it
// in quotes, or (Unix shells) backslash-escapes spaces and the like.
func cleanPastedPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	} else if runtime.GOOS != "windows" {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		s = b.String()
	}
	if strings.HasPrefix(s, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			s = filepath.Join(home, s[2:])
		}
	}
	return s
}

// promptReader: the install one-liner runs us as `curl ... | sh -s -- open
// LINK`, where stdin is the (finished) script pipe - ask on the terminal
// itself then. Falls back to stdin when there is no terminal.
func promptReader() *bufio.Reader {
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		return bufio.NewReader(os.Stdin)
	}
	tty := "/dev/tty"
	if runtime.GOOS == "windows" {
		tty = "CONIN$"
	}
	if f, err := os.Open(tty); err == nil {
		return bufio.NewReader(f)
	}
	return bufio.NewReader(os.Stdin)
}

func runOpenSend(link string) {
	sl, err := parseSendLink(link)
	if err != nil {
		die(err)
	}
	fmt.Printf("beamdrop %s - taking over a send from the browser\n\n", Version)
	fmt.Printf("Looking for %q (%s)...\n", sl.name, formatBytes(sl.size))
	in := promptReader()
	path := locateSendFile(sl)
	if path == "" {
		fmt.Println("Could not find it automatically.")
		for tries := 0; path == ""; tries++ {
			if tries >= 5 {
				die(fmt.Errorf("giving up - nothing was sent"))
			}
			fmt.Print("Drag the file into this window and press Enter (empty line cancels): ")
			line, rerr := in.ReadString('\n')
			p := cleanPastedPath(line)
			if p == "" {
				die(fmt.Errorf("cancelled - nothing was sent"))
			}
			if cerr := checkSendCandidate(p, sl); cerr != nil {
				fmt.Printf("Not sending %s: %v\n", p, cerr)
				if rerr != nil {
					die(fmt.Errorf("no matching file - nothing was sent"))
				}
				continue
			}
			path = p
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	// Always ask: the link came from a web page and makes us send a local file.
	fmt.Printf("\nFound: %s (%s)\n", path, formatBytes(sl.size))
	fmt.Print("Send this file? [y/N] ")
	ans, _ := in.ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
		die(fmt.Errorf("not confirmed - nothing was sent"))
	}
	fmt.Println()

	sendArgs := []string{"--server", sl.server}
	if sl.relay {
		sendArgs = append(sendArgs, "--relay")
	}
	sendArgs = append(sendArgs, path)
	// If a new receiver replaces the current one, runSend re-executes
	// os.Args: make that a plain `send` (no second search / prompt).
	os.Args = append([]string{os.Args[0], "send"}, sendArgs...)
	pendingTakeover = &handoff{room: sl.room, key: sl.key, takeover: true, chunk: sl.chunk, name: sl.name}
	runSend(sendArgs)
	holdWindowIfNeeded()
}
