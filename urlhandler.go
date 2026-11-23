package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
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
	args[0] = stripPastedQuotes(args[0])
	announceLinkLaunch(args[0])
	autoUpdateForLink()
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

// autoUpdateForLink brings the CLI up to the latest release before a link
// launch does its work. Link launches come from the web page, which is always
// the newest version and may rely on things an old CLI does not know (a
// v0.8.3 CLI could not find a deeply nested file that v0.8.6 finds at once),
// and nobody thinks of running `beamdrop update` first. Best effort: any
// failure just continues with the installed version. The other side waits
// minutes for us, so the few seconds a download takes are fine.
// BEAMDROP_NO_AUTOUPDATE=1 (or BEAMDROP_NO_UPDATE_CHECK=1) turns it off.
func autoUpdateForLink() {
	if os.Getenv("BEAMDROP_NO_AUTOUPDATE") == "1" || os.Getenv("BEAMDROP_NO_UPDATE_CHECK") == "1" ||
		os.Getenv("BEAMDROP_UPDATED") == "1" || strings.Contains(Version, "-") {
		return // opted out, just updated, or a dev build
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/s-saga011/beamdrop-cli/releases/latest")
	if err != nil {
		return
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	derr := json.NewDecoder(resp.Body).Decode(&rel)
	resp.Body.Close()
	latest := strings.TrimSpace(rel.TagName)
	if derr != nil || resp.StatusCode != 200 || latest == "" || !versionLess(Version, latest) {
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if r, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = r
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	url := fmt.Sprintf("https://github.com/s-saga011/beamdrop-cli/releases/download/%s/beamdrop-%s-%s%s", latest, runtime.GOOS, runtime.GOARCH, ext)
	fmt.Printf("Updating beamdrop %s -> %s first...\n", Version, latest)
	tmp := exePath + ".new"
	_ = os.Remove(tmp)
	if err := downloadTo(url, tmp); err != nil {
		_ = os.Remove(tmp)
		fmt.Printf("Update skipped (%v) - continuing with %s.\n", err, Version)
		return
	}
	if err := atomicReplaceBinary(exePath, tmp); err != nil {
		_ = os.Remove(tmp)
		fmt.Printf("Update skipped (%v) - continuing with %s.\n", err, Version)
		return
	}
	// Run the new binary with the same arguments; the marker prevents a loop
	// if the release somehow still reports an older version.
	if err := reexec(append(os.Environ(), "BEAMDROP_UPDATED=1")); err != nil {
		fmt.Printf("Updated to %s, but could not restart (%v) - continuing with %s.\n", latest, err, Version)
	}
}

var linkRoomRe = regexp.MustCompile(`^beamdrop://([A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?)/[rs]/([A-Za-z0-9_-]{1,64})[?#]`)

// announceLinkLaunch tells the signaling server "the app started for this
// room". The web page that opened the link has left the room and cannot see
// us; it polls for this so it can say "handed off" instead of guessing, or -
// when nothing arrives - switch to the install instructions. Sent first,
// before the self-update and (for sends) the file search and y/N prompt,
// which can take a while. Best effort, trusted hosts only.
func announceLinkLaunch(link string) {
	m := linkRoomRe.FindStringSubmatch(link)
	if m == nil || !linkAllowedHosts()[m[1]] {
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(linkServerURL(m[1])+"/api/rooms/"+m[2]+"/app", "application/json", nil)
	if err == nil {
		resp.Body.Close()
	}
}
