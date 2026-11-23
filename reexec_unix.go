//go:build !windows

package main

import (
	"os"
	"syscall"
)

// reexec replaces this process with a fresh copy of itself.
func reexec(env []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, env)
}
