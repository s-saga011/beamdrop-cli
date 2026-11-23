//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS only routes URL schemes to app bundles, never to a bare binary. So we
// generate a tiny background applet with osacompile (ships with macOS) whose
// only job is to receive the link and run `beamdrop open <link>` in a
// Terminal window. It must live in an Applications folder — LaunchServices
// ignores bundles under temp dirs. Built locally, so no quarantine/Gatekeeper.
const (
	linkAppName  = "Beamdrop Link.app"
	linkBundleID = "com.beamdrop.link"
	lsregister   = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
)

func linkAppPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Applications", linkAppName), nil
}

// asQuote renders s as an AppleScript string literal.
func asQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func registerLinkHandler(exe string) error {
	app, err := linkAppPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(app), 0o755); err != nil {
		return err
	}
	// The link is attacker-influenced: it only ever travels through
	// `quoted form of`, and `beamdrop open` validates it again.
	// Terminal runs a throwaway .command file (deleted by its own first
	// line) — unlike `tell application "Terminal"`, that needs no Automation
	// permission prompt.
	script := `on open location theURL
	set f to (do shell script "mktemp -t beamdrop-link") & ".command"
	set body to "exec " & quoted form of ` + asQuote(exe) + ` & " open " & quoted form of theURL
	do shell script "printf '%s\\n' '#!/bin/sh' 'rm -f \"$0\" \"${0%.command}\"' " & quoted form of body & " > " & quoted form of f & " && chmod 700 " & quoted form of f & " && open -a Terminal " & quoted form of f
end open location
`
	src, err := os.CreateTemp("", "beamdrop-link-*.applescript")
	if err != nil {
		return err
	}
	defer os.Remove(src.Name())
	if _, err := src.WriteString(script); err != nil {
		return err
	}
	src.Close()

	_ = os.RemoveAll(app)
	plist := filepath.Join(app, "Contents", "Info.plist")
	steps := [][]string{
		{"osacompile", "-o", app, src.Name()},
		{"plutil", "-replace", "CFBundleURLTypes", "-json",
			`[{"CFBundleURLName":"beamdrop link","CFBundleURLSchemes":["` + linkScheme + `"]}]`, plist},
		{"plutil", "-replace", "CFBundleIdentifier", "-string", linkBundleID, plist},
		{"plutil", "-replace", "LSUIElement", "-bool", "true", plist}, // no Dock icon
		{"codesign", "--force", "-s", "-", app},                       // re-seal after editing Info.plist
		{lsregister, "-f", app},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", s[0], err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func unregisterLinkHandler() error {
	app, err := linkAppPath()
	if err != nil {
		return err
	}
	_ = exec.Command(lsregister, "-u", app).Run()
	return os.RemoveAll(app)
}
