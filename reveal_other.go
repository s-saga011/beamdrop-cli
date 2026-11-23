//go:build !windows

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

// revealFile shows a received file in the OS file manager. Best effort.
func revealFile(path string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", "-R", path)
	} else {
		// No portable "select this file": open the containing folder.
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return
		}
		cmd = exec.Command("xdg-open", filepath.Dir(path))
	}
	dbgf("[reveal] %v\n", cmd.Args)
	if err := cmd.Run(); err != nil {
		dbgf("[reveal] failed: %v\n", err)
	}
}
