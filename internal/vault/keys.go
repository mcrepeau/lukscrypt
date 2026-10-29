package vault

import (
	"fmt"
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
