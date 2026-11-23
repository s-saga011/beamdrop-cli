//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const linkDesktopFile = "beamdrop-link.desktop"

func linkDesktopPath() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "applications", linkDesktopFile), nil
}

func registerLinkHandler(exe string) error {
	p, err := linkDesktopPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// Desktop-entry Exec quoting: wrap in double quotes, escape \ " ` $.
	q := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(exe) + `"`
	// %u is passed as one argv element (no shell), and `beamdrop open`
	// validates it. Terminal=true gives the progress bar a window.
	entry := "[Desktop Entry]\nType=Application\nName=beamdrop link handler\n" +
		"Exec=" + q + " open %u\nTerminal=true\nNoDisplay=true\n" +
		"MimeType=x-scheme-handler/" + linkScheme + ";\n"
	if err := os.WriteFile(p, []byte(entry), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("xdg-mime", "default", linkDesktopFile, "x-scheme-handler/"+linkScheme).CombinedOutput(); err != nil {
		return fmt.Errorf("xdg-mime: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("update-desktop-database", filepath.Dir(p)).Run() // best effort
	return nil
}

func unregisterLinkHandler() error {
	p, err := linkDesktopPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = exec.Command("update-desktop-database", filepath.Dir(p)).Run()
	// `xdg-mime default` recorded us in mimeapps.list and has no inverse;
	// drop our line so the scheme doesn't point at a missing .desktop file.
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg = filepath.Join(home, ".config")
		}
	}
	for _, f := range []string{filepath.Join(cfg, "mimeapps.list"), filepath.Join(filepath.Dir(p), "mimeapps.list")} {
		dropMimeDefault(f)
	}
	return nil
}

// dropMimeDefault removes our x-scheme-handler line from one mimeapps.list,
// leaving every other line (and other handlers for the scheme) untouched.
func dropMimeDefault(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	ours := "x-scheme-handler/" + linkScheme + "=" + linkDesktopFile
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	changed := false
	for _, l := range lines {
		if t := strings.TrimSuffix(strings.TrimSpace(l), ";"); t == ours {
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	if changed {
		_ = os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o644)
	}
}
