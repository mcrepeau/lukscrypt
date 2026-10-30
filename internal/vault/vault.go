// Package vault implements LUKS encrypted vault operations: creating, opening,
// closing and deleting image-backed encrypted filesystems via cryptsetup, dd,
// and the standard Linux mount utilities.
package vault

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
// ctx cancellation interrupts any in-progress subprocess (fallocate, dd,
// cryptsetup, mkfs, mount) and triggers cleanup of partial state.
func Create(ctx context.Context, database *db.DB, name, path string, sizeGB int, password, mountPoint string, ch chan<- ProgressEvent) {
	defer close(ch)

	send := func(step, msg string, pct int) {
		select {
		case ch <- ProgressEvent{Step: step, Message: msg, Percent: pct}:
		default:
		}
	}
	// sendTerminal delivers the final event (done or error). Unlike progress
	// sends it blocks: a slow SSE reader must not lose the terminal event and
	// end up showing "Connection lost" for a successful creation. It still
	// escapes on shutdown, or if no reader ever connected and the buffer is
	// full of unread progress events.
	sendTerminal := func(ev ProgressEvent) {
		select {
		case ch <- ev:
		case <-ctx.Done():
		case <-time.After(time.Minute):
		}
	}
	fail := func(context string, err error) {
		sendTerminal(ProgressEvent{Error: fmt.Sprintf("%s: %v", context, err)})
	}

	imgPath := filepath.Join(path, name+".img")
	mapperName := name

	if err := os.MkdirAll(path, 0750); err != nil {
		fail("create storage directory", err)
		return
	}

	// Fail fast if there is not enough free space on the target filesystem.
	if err := checkDiskSpace(path, sizeGB); err != nil {
		fail("disk space check", err)
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

	// Step 1: allocate container file (fallocate if available, dd otherwise)
	send("creating", fmt.Sprintf("Allocating %d GB container file...", sizeGB), 0)
	if err := allocateFile(ctx, imgPath, sizeGB, ch); err != nil {
		fail("create container file", err)
		os.Remove(imgPath)
		return
	}

	// Step 2: LUKS format
	send("encrypting", "Encrypting vault with LUKS...", 62)
	cmd := exec.CommandContext(ctx, "cryptsetup", "luksFormat", "--batch-mode", imgPath)
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		fail(fmt.Sprintf("luksFormat (%s)", strings.TrimSpace(string(out))), err)
		os.Remove(imgPath)
		return
	}

	// Step 3: open LUKS device
	send("opening", "Opening LUKS device...", 75)
	cmd = exec.CommandContext(ctx, "cryptsetup", "luksOpen", imgPath, mapperName)
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
	cmd = exec.CommandContext(ctx, "mkfs.ext4", "-L", label, "/dev/mapper/"+mapperName)
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
	cmd = exec.CommandContext(ctx, "mount", "/dev/mapper/"+mapperName, mountPoint)
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
		os.Remove(mountPoint)
		return
	}

	// Step 6: persist to database
	vault, err := database.CreateVault(name, imgPath, sizeGB, mountPoint, mapperName)
	if err != nil {
		exec.Command("umount", mountPoint).Run()
		exec.Command("cryptsetup", "luksClose", mapperName).Run()
		fail("save vault to database", err)
		os.Remove(imgPath)
		os.Remove(mountPoint)
		return
	}

	sendTerminal(ProgressEvent{
		Step:    "done",
		Message: "Vault created and mounted successfully!",
		Percent: 100,
		Done:    true,
		VaultID: vault.ID,
	})
}

// allocateFile creates the backing image file. It first attempts fallocate,
// which is near-instantaneous on most Linux filesystems. If fallocate is
// unavailable or the filesystem doesn't support it (NFS, some older FS types),
// it falls back to dd which zeroes every block and reports real progress.
func allocateFile(ctx context.Context, imgPath string, sizeGB int, ch chan<- ProgressEvent) error {
	size := int64(sizeGB) * 1024 * 1024 * 1024
	cmd := exec.CommandContext(ctx, "fallocate", "-l", fmt.Sprintf("%d", size), imgPath)
	if err := cmd.Run(); err == nil {
		select {
		case ch <- ProgressEvent{Step: "creating", Message: "Container file allocated.", Percent: 60}:
		default:
		}
		return nil
	}
	// fallocate failed — clean up any partial file it may have left, then use dd.
	os.Remove(imgPath)
	return createFile(ctx, imgPath, sizeGB, ch)
}

// createFile runs dd and monitors file growth to send progress updates to ch.
func createFile(ctx context.Context, imgPath string, sizeGB int, ch chan<- ProgressEvent) error {
	cmd := exec.CommandContext(ctx, "dd",
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
		case <-ctx.Done():
			// Context cancelled (server shutting down). CommandContext will
			// send SIGKILL to dd; wait for it to actually exit before
			// returning so the caller can safely remove the partial file.
			<-errCh
			return ctx.Err()
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
	return UnlockContext(context.Background(), v, password)
}

// UnlockContext is Unlock bounded by ctx: the cryptsetup and mount
// subprocesses are interrupted (SIGKILL) if ctx is cancelled or times out, so
// an in-flight unlock cannot stall the HTTP drain on shutdown. The cleanup
// luksClose still runs unconditionally (it must, to not leak the mapper).
func UnlockContext(ctx context.Context, v *db.Vault, password string) error {
	return unlockWith(ctx, v, strings.NewReader(password))
}

// UnlockKeyFile opens the LUKS device using raw keyfile bytes as the
// credential. The bytes are piped to cryptsetup's stdin (--key-file=-) and
// never touch the filesystem. --keyfile-size pins the exact byte count so
// binary content (including embedded newlines) is used verbatim and a
// truncated read fails instead of silently becoming a shorter credential.
func UnlockKeyFile(v *db.Vault, key []byte) error {
	return UnlockKeyFileContext(context.Background(), v, key)
}

// UnlockKeyFileContext is UnlockKeyFile bounded by ctx (see UnlockContext).
func UnlockKeyFileContext(ctx context.Context, v *db.Vault, key []byte) error {
	return unlockWith(ctx, v, bytes.NewReader(key),
		"--key-file=-", "--keyfile-size="+strconv.Itoa(len(key)))
}

// unlockWith is the shared unlock path: extraArgs are cryptsetup options
// inserted before the device path, and stdin carries the credential.
func unlockWith(ctx context.Context, v *db.Vault, stdin io.Reader, extraArgs ...string) error {
	if IsUnlocked(v) {
		return fmt.Errorf("vault is already unlocked")
	}

	args := append([]string{"luksOpen"}, extraArgs...)
	args = append(args, v.Path, v.MapperName)
	cmd := exec.CommandContext(ctx, "cryptsetup", args...)
	cmd.Stdin = stdin
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksOpen: %s", strings.TrimSpace(string(out)))
	}

	if err := os.MkdirAll(v.MountPoint, 0750); err != nil {
		exec.Command("cryptsetup", "luksClose", v.MapperName).Run()
		return fmt.Errorf("create mount point: %w", err)
	}

	cmd = exec.CommandContext(ctx, "mount", "/dev/mapper/"+v.MapperName, v.MountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		exec.Command("cryptsetup", "luksClose", v.MapperName).Run()
		return fmt.Errorf("mount: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Lock closes a LUKS device, unmounting it first if currently mounted.
// It handles the unlocked-but-not-mounted state (e.g. after a failed mount or
// a manual umount) by skipping the umount step when nothing is mounted.
func Lock(v *db.Vault) error {
	return LockContext(context.Background(), v)
}

// LockContext is Lock bounded by ctx: the umount and luksClose subprocesses
// are interrupted (SIGKILL) if ctx is cancelled or times out. Used by the
// graceful-shutdown path so a busy mount cannot stall the whole exit.
func LockContext(ctx context.Context, v *db.Vault) error {
	mounts := ReadMounts()
	unlocked, mounted := StatusIn(v, mounts)
	if !unlocked {
		return fmt.Errorf("vault is already locked")
	}
	if mounted {
		if out, err := exec.CommandContext(ctx, "umount", v.MountPoint).CombinedOutput(); err != nil {
			return fmt.Errorf("umount: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.CommandContext(ctx, "cryptsetup", "luksClose", v.MapperName).CombinedOutput(); err != nil {
		return fmt.Errorf("luksClose: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// VaultLockError pairs a vault name with the error that prevented locking it
// during shutdown, so the caller can log exactly which vaults remain open.
type VaultLockError struct {
	Vault string
	Err   error
}

// isUnlocked is a package-level indirection over IsUnlocked so tests can
// simulate unlocked vaults without real device-mapper entries.
var isUnlocked = IsUnlocked

// LockAllUnlocked locks every vault that is currently unlocked, unmounting
// first where needed. It exists for graceful shutdown: a container restart
// must not leave stale device-mapper or loop devices on the host kernel
// (they outlive the container). Failures are collected per vault and
// returned — a partial cleanup is better than none, and the caller must
// still exit. Each vault gets its own timeout so one busy mount cannot
// consume the whole budget.
func LockAllUnlocked(ctx context.Context, database *db.DB) []VaultLockError {
	vaults, err := database.ListVaults()
	if err != nil {
		return []VaultLockError{{Vault: "(list vaults)", Err: err}}
	}
	var failures []VaultLockError
	for i := range vaults {
		v := vaults[i]
		if !isUnlocked(&v) {
			continue
		}
		opCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := LockContext(opCtx, &v); err != nil {
			failures = append(failures, VaultLockError{Vault: v.Name, Err: err})
		}
		cancel()
	}
	return failures
}

// Mount mounts an already-unlocked vault at its configured mount point.
// Returns an error if the vault is not unlocked or is already mounted.
func Mount(v *db.Vault) error {
	mounts := ReadMounts()
	unlocked, mounted := StatusIn(v, mounts)
	if !unlocked {
		return fmt.Errorf("vault is not unlocked")
	}
	if mounted {
		return fmt.Errorf("vault is already mounted")
	}
	if err := os.MkdirAll(v.MountPoint, 0750); err != nil {
		return fmt.Errorf("create mount point: %w", err)
	}
	cmd := exec.Command("mount", "/dev/mapper/"+v.MapperName, v.MountPoint)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mount: %s", strings.TrimSpace(string(out)))
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

// ReadMounts reads /proc/mounts once and returns the raw bytes. Pass the result
// to StatusIn when checking multiple vaults in a single request to avoid
// repeated file reads.
func ReadMounts() []byte {
	data, _ := os.ReadFile("/proc/mounts")
	return data
}

// StatusIn derives the unlocked and mounted status for v from a pre-read
// /proc/mounts snapshot. Use this in loops; use IsUnlocked/IsMounted for
// single-vault paths where a fresh read is fine.
func StatusIn(v *db.Vault, mounts []byte) (unlocked, mounted bool) {
	mounted = mountedIn(v.MountPoint, mounts)
	if _, err := os.Stat("/dev/mapper/" + v.MapperName); err == nil {
		unlocked = true
	} else {
		unlocked = mounted
	}
	return unlocked, mounted
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

// IsMounted reports whether the vault's filesystem is currently mounted.
// It matches against the mount point path (column 2 of /proc/mounts) rather
// than the device name because:
//   - after a container restart, propagated host mounts may appear as /dev/dm-N
//     rather than /dev/mapper/<name>, making a device-name search unreliable;
//   - mount-point matching with space delimiters avoids false substring matches
//     when one vault name is a prefix of another (e.g. "data" vs "data-2").
func IsMounted(v *db.Vault) bool {
	return mountedIn(v.MountPoint, ReadMounts())
}

// mountedIn checks whether mountPoint appears as a mount destination in the
// given /proc/mounts snapshot. Space delimiters prevent false prefix matches.
func mountedIn(mountPoint string, mounts []byte) bool {
	return bytes.Contains(mounts, []byte(" "+mountPoint+" "))
}

