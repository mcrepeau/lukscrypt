//go:build linux

package vault

import "syscall"

// DiskUsage returns (usedBytes, totalBytes) for the filesystem at mountPoint.
// Returns (0, 0) if the stat call fails.
func DiskUsage(mountPoint string) (used, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &st); err != nil {
		return 0, 0
	}
	bsize := int64(st.Bsize)
	total = int64(st.Blocks) * bsize
	used = (int64(st.Blocks) - int64(st.Bfree)) * bsize
	return used, total
}
