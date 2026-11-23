//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func platformNeedsASCII() bool {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return true // piped or redirected
	}
	// A real console. Turn on ANSI escapes (the progress line uses ESC[K);
	// harmless if it is already on or unsupported.
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if os.Getenv("WT_SESSION") != "" {
		return false // Windows Terminal renders Unicode fine
	}
	cp, err := windows.GetConsoleOutputCP()
	return err != nil || cp != 65001
}
