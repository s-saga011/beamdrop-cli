//go:build windows

package main

import (
	"golang.org/x/sys/windows/registry"
)

const linkRegKey = `Software\Classes\` + linkScheme

// Per-user registration under HKCU — no admin rights.
//
// The command line is `"<exe>" open "%1"`, started directly by the shell
// (CreateProcess), NOT through cmd.exe: a link may contain & | ^ and cmd
// would execute what follows them. The console window Windows opens for us
// closes on exit, so `beamdrop open` waits for Enter itself.
func registerLinkHandler(exe string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, linkRegKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("", "URL:beamdrop link"); err != nil {
		return err
	}
	if err := k.SetStringValue("URL Protocol", ""); err != nil {
		return err
	}
	c, _, err := registry.CreateKey(registry.CURRENT_USER, linkRegKey+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.SetStringValue("", `"`+exe+`" open "%1"`)
}

func unregisterLinkHandler() error {
	for _, sub := range []string{`\shell\open\command`, `\shell\open`, `\shell`, ``} {
		if err := registry.DeleteKey(registry.CURRENT_USER, linkRegKey+sub); err != nil && err != registry.ErrNotExist {
			return err
		}
	}
	return nil
}
