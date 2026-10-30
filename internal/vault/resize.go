package vault

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"lukscrypt/internal/db"
)

// Grow extends a vault's image file, LUKS device and ext4 filesystem to
// sizeGB. The vault must be unlocked — the dm device must be open — and the
// operation is online-safe while mounted (resize2fs grows ext4 live).
//
// key is the unlock credential (raw passphrase or keyfile bytes).
// cryptsetup resize must re-derive the volume key to reload the dm table;
// on a normal host LUKS2 can take it from the kernel session keyring, but
// keyrings are unreliable inside containers, so the credential is always
// provided explicitly via stdin (--key-file=-, exact --keyfile-size).
//
// Grow-only by design: ext4 cannot shrink online, and an automated shrink
// (umount, fsck, resize2fs down, truncate) is too data-destructive to
// automate for a NAS product.
//
// Each step can fail independently and all failure states are recoverable
// by re-running grow after a lock/unlock cycle: a failed image extension
// changes nothing; a failed cryptsetup resize leaves an extended image with
// a stale device size; a failed resize2fs leaves a resized device with a
// stale filesystem.
func Grow(ctx context.Context, v *db.Vault, sizeGB int, key []byte) error {
	delta := sizeGB - v.SizeGB
	if delta <= 0 {
		return fmt.Errorf("new size must be greater than the current size of %d GB", v.SizeGB)
	}
	if err := checkDiskSpace(v.Path, delta); err != nil {
		return err
	}

	// Step 1: extend the image file. fallocate is near-instantaneous on
	// normal filesystems; on filesystems without fallocate support (NFS,
	// older FS types) fall back to dd appending the delta with conv=notrunc.
	size := int64(sizeGB) * 1024 * 1024 * 1024
	if out, err := exec.CommandContext(ctx, "fallocate", "-l", fmt.Sprintf("%d", size), v.Path).CombinedOutput(); err != nil {
		if err := appendFile(ctx, v.Path, delta); err != nil {
			return fmt.Errorf("extend image (%s): %w", strings.TrimSpace(string(out)), err)
		}
	}

	// Step 2: resize the LUKS device. For file-backed vaults cryptsetup
	// re-reads the backing size, including updating the loop device
	// capacity, so the dm device sees the extended image. The credential
	// on stdin supplies the volume key.
	cmd := exec.CommandContext(ctx, "cryptsetup", "resize",
		"--key-file=-", "--keyfile-size="+strconv.Itoa(len(key)), v.MapperName)
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cryptsetup resize: %s", strings.TrimSpace(string(out)))
	}

	// Step 3: grow the ext4 filesystem (online while mounted).
	if out, err := exec.CommandContext(ctx, "resize2fs", "/dev/mapper/"+v.MapperName).CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// appendFile extends the image by deltaGB with dd, appending after the
// current content (conv=notrunc). Used only when fallocate is unavailable.
func appendFile(ctx context.Context, path string, deltaGB int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	offsetMB := info.Size() / (1024 * 1024)
	cmd := exec.CommandContext(ctx, "dd",
		"if=/dev/zero",
		"of="+path,
		"bs=1M",
		fmt.Sprintf("seek=%d", offsetMB),
		fmt.Sprintf("count=%d", deltaGB*1024),
		"conv=notrunc",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}
