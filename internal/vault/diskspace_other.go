//go:build !linux

package vault

// checkDiskSpace is a no-op on non-Linux platforms. The app only runs on
// Linux in production; this stub exists solely to allow go build/vet on
// development machines running other OSes.
func checkDiskSpace(path string, sizeGB int) error {
	return nil
}
