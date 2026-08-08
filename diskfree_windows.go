//go:build windows

package main

// diskFree is not implemented on Windows; the mid-transfer write-failure
// path still surfaces disk-full errors loudly.
func diskFree(path string) int64 { return -1 }
