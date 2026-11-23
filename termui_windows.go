//go:build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetConsoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	procGetClassNameW    = windows.NewLazySystemDLL("user32.dll").NewProc("GetClassNameW")
)

// hostedByModernTerminal reports whether our console is a pseudoconsole,
// i.e. drawn by Windows Terminal, VS Code or another ConPTY host rather than
// the classic conhost window. WT_SESSION alone misses the common case: on
// Windows 11 a PowerShell opened from the Start menu (or by a beamdrop://
// link) is handed off to Windows Terminal without that variable being set.
func hostedByModernTerminal() bool {
	if os.Getenv("WT_SESSION") != "" {
		return true
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return false
	}
	buf := make([]uint16, 64)
	n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return n > 0 && windows.UTF16ToString(buf[:n]) == "PseudoConsoleWindow"
}

func platformNeedsASCII() bool {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		outputIsTerminal = false
		return true // piped or redirected: PowerShell would mis-decode UTF-8
	}
	// A real console. Turn on ANSI escapes (the progress line uses ESC[K);
	// harmless if it is already on or unsupported.
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if hostedByModernTerminal() {
		return false
	}
	// Classic conhost: fine with a UTF-8 code page, but under a CJK code
	// page block characters render double-width and the QR code is ruined.
	cp, err := windows.GetConsoleOutputCP()
	return err != nil || cp != 65001
}
