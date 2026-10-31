package vault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"lukscrypt/internal/db"
)

// MaxKeySlot is the highest keyslot index accepted. LUKS2 supports 32 slots
// (0-31); LUKS1 supports only 8, but cryptsetup rejects out-of-range slots
// for LUKS1 headers itself and the error surfaces as a 422.
const MaxKeySlot = 31

// AddKey adds a passphrase keyslot to the vault's LUKS header. oldPassword
// must match an existing valid keyslot; the new slot wraps a new copy of the
// same master key, so the data area is untouched. slot < 0 lets cryptsetup
// pick the first free slot. Works on locked and unlocked vaults alike — only
// the header is modified — but callers must still serialize under opMu.
func AddKey(v *db.Vault, oldPassword, newPassword string, slot int) error {
	args := []string{"luksAddKey", "--batch-mode", v.Path}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	cmd := exec.Command("cryptsetup", args...)
	// --batch-mode suppresses the retype prompt; stdin then carries the
	// existing passphrase followed by the new one.
	cmd.Stdin = strings.NewReader(oldPassword + "\n" + newPassword + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksAddKey: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// MaxKeyFileSize caps uploaded keyfiles (base64-decoded). A good keyfile is a
// few dozen bytes; 1 MiB is a generous ceiling that keeps request bodies
// small (cryptsetup's own default maximum is 8 MiB).
const MaxKeyFileSize = 1024 * 1024

// MinKeyFileSize mirrors the 8-character password policy: the keyfile content
// is the credential itself, so a shorter file would be strictly weaker than
// the weakest password the API accepts.
const MinKeyFileSize = 8

// AddKeyFile adds a keyslot whose new credential is raw keyfile bytes.
// existing may be either a typed passphrase or keyfile bytes — both are fed
// via stdin as the existing-key keyfile (--key-file=-, exact --keyfile-size).
// cryptsetup has no two-input stdin mode, so the new credential must be a
// file for its positional argument: it goes through a 0600 temp file that is
// removed immediately after the command exits.
func AddKeyFile(v *db.Vault, existing, newKey []byte, slot int) error {
	tmp, err := os.CreateTemp("", "lukscrypt-key-")
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		// Wipe the key material before unlinking: if the process is SIGKILLed
		// between now and the remove, the file would survive in /tmp with the
		// credential in it.
		os.WriteFile(tmpPath, make([]byte, len(newKey)), 0o600)
		os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temp key file: %w", err)
	}
	if _, err := tmp.Write(newKey); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write temp key file: %w", err)
	}

	args := []string{"luksAddKey", "--batch-mode", "--key-file=-", "--keyfile-size=" + strconv.Itoa(len(existing))}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	args = append(args, v.Path, tmpPath)
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytes.NewReader(existing)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksAddKey: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// KillSlot removes the keyslot at index slot. remainingPassword must match
// a different, still-valid keyslot — killing the last valid slot would
// destroy the only remaining wrapped copy of the master key and make the
// data permanently unrecoverable. Enforced by ValidateKillSlot before this
// runs, and by cryptsetup as a second line of defense.
func KillSlot(v *db.Vault, remainingPassword string, slot int) error {
	cmd := exec.Command("cryptsetup", "luksKillSlot", v.Path, strconv.Itoa(slot))
	cmd.Stdin = strings.NewReader(remainingPassword)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksKillSlot: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// KillSlotKeyFile is KillSlot with a raw keyfile as the remaining credential:
// the bytes go to cryptsetup's stdin via --key-file=- with an exact
// --keyfile-size, so binary content is used verbatim. Needed when the only
// other valid keyslot is keyfile-based (a passphrase cannot prove authority
// for a keyfile slot and vice versa).
func KillSlotKeyFile(v *db.Vault, key []byte, slot int) error {
	cmd := exec.Command("cryptsetup", "luksKillSlot",
		"--key-file=-", "--keyfile-size="+strconv.Itoa(len(key)),
		v.Path, strconv.Itoa(slot))
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("luksKillSlot: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ValidateKillSlot reports whether slot may be removed from the header
// described by d: it must be a valid slot (LUKS2 lists only valid slots,
// LUKS1 lists both "enabled" and "disabled") and must not be the last
// valid one. Checked server-side so the UI gets a clear error message
// instead of cryptsetup's.
func ValidateKillSlot(d *LUKSDetails, slot int) error {
	valid := 0
	found := false
	for _, ks := range d.KeySlots {
		if ks.Status == "valid" || ks.Status == "enabled" {
			valid++
			if ks.Index == slot {
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("keyslot %d is not a valid keyslot", slot)
	}
	if valid <= 1 {
		return fmt.Errorf("cannot remove the last valid keyslot — the vault would become permanently inaccessible")
	}
	return nil
}
