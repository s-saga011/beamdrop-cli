//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// revealFile shows a received file in Explorer. Best effort: explorer.exe
// exits non-zero even on success, so the result is ignored. The command line
// is given verbatim (no cmd.exe; Go's own quoting would wrap the whole
// "/select,..." argument, which Explorer does not parse). A Windows path
// cannot contain a double quote.
func revealFile(path string) {
	cmd := exec.Command("explorer.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + path + `"`}
	_ = cmd.Run()
}
