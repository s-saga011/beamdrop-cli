//go:build !windows

package main

func platformNeedsASCII() bool { return false }
