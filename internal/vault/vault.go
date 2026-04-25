// Package vault implements LUKS encrypted vault operations: creating, opening,
// closing and deleting image-backed encrypted filesystems via cryptsetup, dd,
// and the standard Linux mount utilities.
package vault

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lukscrypt/internal/db"
)

// ProgressEvent is sent over SSE during vault creation.
type ProgressEvent struct {
	Step    string `json:"step"`
	Message string `json:"message"`
	Percent int    `json:"percent"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
	VaultID int64  `json:"vault_id,omitempty"`
}

// Create runs the full vault creation pipeline and streams progress to ch.
// ch is closed when the operation completes (successfully or not).
func Create(database *db.DB, name, path string, sizeGB int, password, mountPoint string, ch chan<- ProgressEvent) {
	defer close(ch)

	send := func(step, msg string, pct int) {
		select {
		case ch <- ProgressEvent{Step: step, Message: msg, Percent: pct}:
		default:
		}
	}
	fail := func(context string, err error) {
		select {
		case ch <- ProgressEvent{Error: fmt.Sprintf("%s: %v", context, err)}:
		default:
		}
	}

	imgPath := filepath.Join(path, name+".img")
	mapperName := sanitizeName(name)

	if err := os.MkdirAll(path, 0750); err != nil {
		fail("create storage directory", err)
		return
	}

	// Fail fast if the image file already exists.
	if _, err := os.Stat(imgPath); err == nil {
		fail("create container file", fmt.Errorf("file %s already exists", imgPath))
		return
	}

	// Fail fast if the mapper device is already active (e.g. leftover from a
	// previous failed attempt or another open vault with the same name).
	if _, err := os.Stat("/dev/mapper/" + mapperName); err == nil {
		fail("open LUKS device", fmt.Errorf("/dev/mapper/%s already exists — close it first or choose a different vault name", mapperName))
		return
	}

	// Step 1: create container file with dd, reporting real progress
	send("creating", fmt.Sprintf("Creating %d GB container file...", sizeGB), 0)
	if err := createFile(imgPath, sizeGB, ch); err != nil {
		fail("create container file", err)
		os.Remove(imgPath)
		return
	}

	// Step 2: LUKS format
	send("encrypting", "Encrypting vault with LUKS...", 62)
	cmd := exec.Command("cryptsetup", "luksFormat", "--batch-mode", imgPath)
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		fail(fmt.Sprintf("luksFormat (%s)", strings.TrimSpace(string(out))), err)
		os.Remove(imgPath)
		return
	}

	// Step 3: open LUKS device
	send("opening", "Opening LUKS device...", 75)
	cmd = exec.Command("cryptsetup", "luksOpen", imgPath, mapperName)
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		fail(fmt.Sprintf("luksOpen (%s)", strings.TrimSpace(string(out))), err)
		os.Remove(imgPath)
		return
	}

	// Step 4: format filesystem
	send("formatting", "Formatting ext4 filesystem...", 85)
	// ext4 volume labels are capped at 16 characters.
	label := name
	if len(label) > 16 {
		label = label[:16]
	}
	cmd = exec.Command("mkfs.ext4", "-L", label, "/dev/mapper/"+mapperName)
	if out, err := cmd.CombinedOutput(); err != nil {
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail(fmt.Sprintf("mkfs.ext4 (%s)", strings.TrimSpace(string(out))), err)
		os.Remove(imgPath)
		return
	}

	// Step 5: create mount point and mount
	send("mounting", "Mounting filesystem...", 95)
	if err := os.MkdirAll(mountPoint, 0750); err != nil {
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail("create mount point", err)
		os.Remove(imgPath)
		return
	}
	cmd = exec.Command("mount", "/dev/mapper/"+mapperName, mountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail(fmt.Sprintf("mount (%s)", strings.TrimSpace(string(out))), err)
		os.Remove(imgPath)
		return
	}
	// Make the root directory of the new filesystem world-writable so that
	// SMB users (and any other non-root accounts) can write to the vault.
	// This chmod is stored inside the ext4 filesystem and persists across
	// lock/unlock cycles — it only needs to be applied once at creation time.
	if err := os.Chmod(mountPoint, 0777); err != nil {
		exec.Command("umount", mountPoint).Run()
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail("set mount point permissions", err)
		os.Remove(imgPath)
		return
	}

	// Step 6: persist to database
	vault, err := database.CreateVault(name, imgPath, sizeGB, mountPoint, mapperName)
	if err != nil {
		exec.Command("umount", mountPoint).Run()
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail("save vault to database", err)
		os.Remove(imgPath)
		return
	}

	select {
	case ch <- ProgressEvent{
		Step:    "done",
		Message: "Vault created and mounted successfully!",
		Percent: 100,
		Done:    true,
		VaultID: vault.ID,
	}:
	default:
	}
}

// createFile runs dd and monitors file growth to send progress updates to ch.
func createFile(imgPath string, sizeGB int, ch chan<- ProgressEvent) error {
	cmd := exec.Command("dd",
		"if=/dev/zero",
		"of="+imgPath,
		"bs=1M",
		fmt.Sprintf("count=%d", sizeGB*1024),
	)
	if err := cmd.Start(); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Wait() }()

	totalBytes := int64(sizeGB) * 1024 * 1024 * 1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			return err
		case <-ticker.C:
			info, err := os.Stat(imgPath)
			if err != nil {
				continue
			}
			// File creation is mapped to 0–60% of the overall progress.
			pct := int(float64(info.Size()) / float64(totalBytes) * 60)
			if pct > 60 {
				pct = 60
			}
			select {
			case ch <- ProgressEvent{
				Step:    "creating",
				Message: fmt.Sprintf("Creating container file... %d%%", pct),
				Percent: pct,
			}:
			default:
			}
		}
	}
}

// Unlock opens a LUKS device and mounts it at the vault's configured mount point.
func Unlock(v *db.Vault, password string) error {
	if IsUnlocked(v) {
		return fmt.Errorf("vault is already unlocked")
	}

	cmd := exec.Command("cryptsetup", "luksOpen", v.Path, v.MapperName)
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksOpen: %s", strings.TrimSpace(string(out)))
	}

	if err := os.MkdirAll(v.MountPoint, 0750); err != nil {
		exec.Command("cryptsetup", "luksClose", v.MapperName).Run()
		return fmt.Errorf("create mount point: %w", err)
	}

	cmd = exec.Command("mount", "/dev/mapper/"+v.MapperName, v.MountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		exec.Command("cryptsetup", "luksClose", v.MapperName).Run()
		return fmt.Errorf("mount: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Lock unmounts and closes a LUKS device.
func Lock(v *db.Vault) error {
	if !IsUnlocked(v) {
		return fmt.Errorf("vault is already locked")
	}

	if out, err := exec.Command("umount", v.MountPoint).CombinedOutput(); err != nil {
		return fmt.Errorf("umount: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("cryptsetup", "luksClose", v.MapperName).CombinedOutput(); err != nil {
		return fmt.Errorf("luksClose: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Delete removes the backing image file and mount point directory.
// The vault must be locked first. os.Remove is used for the directory so it
// fails safely if somehow not empty.
func Delete(v *db.Vault) error {
	if IsUnlocked(v) {
		return fmt.Errorf("vault must be locked before deletion")
	}
	if err := os.Remove(v.Path); err != nil {
		return err
	}
	if err := os.Remove(v.MountPoint); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove mount point: %w", err)
	}
	return nil
}

// IsUnlocked reports whether the LUKS device is open.
// After a container restart the mapper device file may not be visible in the
// container's /dev even though it still exists on the host, so we fall back to
// checking /proc/mounts: a mounted vault must be unlocked.
func IsUnlocked(v *db.Vault) bool {
	if _, err := os.Stat("/dev/mapper/" + v.MapperName); err == nil {
		return true
	}
	return IsMounted(v)
}

// IsMounted reports whether the vault's mapper device is currently mounted.
func IsMounted(v *db.Vault) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "/dev/mapper/"+v.MapperName)
}

// sanitizeName converts a vault name to a safe LUKS mapper identifier.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
