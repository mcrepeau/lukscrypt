//go:build !linux

package vault

// DiskUsage is a no-op stub on non-Linux platforms.
func DiskUsage(_ string) (used, total int64) { return 0, 0 }
