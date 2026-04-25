//go:build linux

package vault

import (
	"fmt"
	"syscall"
)

// checkDiskSpace returns an error if the filesystem containing path has less
// free space than sizeGB gigabytes.
func checkDiskSpace(path string, sizeGB int) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("stat filesystem at %s: %w", path, err)
	}
	available := stat.Bavail * uint64(stat.Bsize)
	required := uint64(sizeGB) * 1024 * 1024 * 1024
	if available < required {
		return fmt.Errorf("insufficient space: need %d GB, only %.1f GB available",
			sizeGB, float64(available)/(1024*1024*1024))
	}
	return nil
}
