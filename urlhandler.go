package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// beamdrop:// links let the web receiver page hand a transfer to an installed
// CLI ("アプリで高速受信"): the browser asks the user, then the OS launches
//
//	beamdrop open beamdrop://HOST/r/ROOM#k=KEY[&relay=1]
//
// which is the https share URL with the scheme swapped.
//
// The link arrives from whatever page the user was on, so treat it as hostile:
// it must match this strict shape (no shell metacharacters can survive it),
// and HOST must be a signaling server we trust, so a random site can't point
// the CLI at its own server. The worst a crafted link can then do is what any
// share link does — offer a file download into ~/Downloads.
var beamdropLinkRe = regexp.MustCompile(
	`^beamdrop://([A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?)/r/([A-Za-z0-9_-]{1,64})#k=([A-Za-z0-9_-]{16,128})(&relay=1)?$`)

const linkScheme = "beamdrop"

func linkAllowedHosts() map[string]bool {
	hosts := map[string]bool{}
	if u, err := url.Parse(defaultServer); err == nil {
		hosts[u.Host] = true
	}
	// Self-hosters: BEAMDROP_LINK_HOSTS=my.example.com,other.example.com
	for _, h := range strings.Split(os.Getenv("BEAMDROP_LINK_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts[h] = true
		}
	}
	return hosts
}

func linkToShareURL(link string) (string, error) {
	m := beamdropLinkRe.FindStringSubmatch(link)
	if m == nil {
		return "", fmt.Errorf("not a valid beamdrop:// link")
	}
	if !linkAllowedHosts()[m[1]] {
		return "", fmt.Errorf("link points at %q, which is not a trusted beamdrop server (set BEAMDROP_LINK_HOSTS to allow it)", m[1])
	}
	return linkServerURL(m[1]) + "/r/" + m[2] + "#k=" + m[3] + m[4], nil
}

// linkServerURL: links carry no scheme. Everything is https except a local
// dev server (which still has to be listed in BEAMDROP_LINK_HOSTS).
func linkServerURL(host string) string {
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	if h == "localhost" || h == "127.0.0.1" {
		return "http://" + host
	}
	return "https://" + host
}

// waitForRoom makes recv retry a full room instead of failing: a link launch
// usually means "take over from the browser tab that was receiving".
var (
	waitForRoom   bool
	roomFullTries int
)

// knockingOnFullRoom: each retry of a full room is a close + re-dial; that
// is the expected rhythm of waiting, not a signaling problem worth a line.
func knockingOnFullRoom() bool { return waitForRoom && roomFullTries > 0 }

// holdWindow is set when we were launched from a link: the terminal window
// was opened just for us and (except on macOS, where Terminal keeps finished
// windows) would vanish with the result before the user can read it.
var holdWindow bool

func holdWindowIfNeeded() {
	if !holdWindow || runtime.GOOS == "darwin" {
		return
	}
	fmt.Print("\nPress Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func runOpen(args []string) {
	holdWindow = true
	if len(args) != 1 {
		die(fmt.Errorf("usage: beamdrop open beamdrop://HOST/r/ROOM#k=KEY"))
	}
	if strings.Contains(args[0], "/s/") {
		runOpenSend(args[0])
		return
	}
	waitForRoom = true
	share, err := linkToShareURL(args[0])
	if err != nil {
		die(err)
	}
	dir := "."
	if home, err := os.UserHomeDir(); err == nil {
		dir = home
		if dl := filepath.Join(home, "Downloads"); isDir(dl) {
			dir = dl
		}
	}
	if err := os.Chdir(dir); err != nil {
		die(fmt.Errorf("cannot enter %s: %w", dir, err))
	}
	fmt.Printf("beamdrop %s - receiving into %s\n\n", Version, dir)
	runRecv([]string{share})
	holdWindowIfNeeded()
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// runRegister points the OS's beamdrop:// handler at this binary. Per-user,
// no admin rights. install.sh / install.ps1 call it; rerun after moving the
// binary. `beamdrop register --remove` undoes it.
func runRegister(args []string) {
	if len(args) == 1 && args[0] == "--remove" {
		if err := unregisterLinkHandler(); err != nil {
			die(err)
		}
		fmt.Println("beamdrop:// links are no longer handled by this CLI.")
		return
	}
	if len(args) != 0 {
		die(fmt.Errorf("usage: beamdrop register [--remove]"))
	}
	exe, err := os.Executable()
	if err != nil {
		die(err)
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	if err := registerLinkHandler(exe); err != nil {
		die(fmt.Errorf("could not register beamdrop:// links: %w", err))
	}
	fmt.Printf("beamdrop:// links now open with %s\n", exe)
}
