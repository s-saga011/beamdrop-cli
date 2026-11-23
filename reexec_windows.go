//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

// reexec: Windows has no exec(), so run a fresh copy as a child on our
// console and stand in for it — stay silent, then exit with its code.
func reexec(env []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	// Our own leftover goroutines must not scribble over the child's output.
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = null, null
	}
	code := 0
	if err := cmd.Wait(); err != nil {
		code = 1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
	}
	os.Exit(code)
	return nil
}
