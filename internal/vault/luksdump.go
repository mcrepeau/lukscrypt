package vault

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"lukscrypt/internal/db"
)

// LUKSDetails is the summary of a vault's LUKS header surfaced in the UI.
type LUKSDetails struct {
	Version     string    `json:"version"` // "1" or "2"
	Cipher      string    `json:"cipher"`  // e.g. "aes-xts-plain64"
	Hash        string    `json:"hash"`    // e.g. "sha256"
	KeySizeBits int       `json:"key_size_bits"`
	UUID        string    `json:"uuid"`
	KeySlots    []KeySlot `json:"keyslots"`
}

// KeySlot describes one LUKS keyslot. Index and Status come from the header;
// Type is the KDF used to derive the slot key (argon2id, pbkdf2, ...).
type KeySlot struct {
	Index  int    `json:"index"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// DumpDetails reads a vault's LUKS header (works whether the vault is locked
// or unlocked — only the header is read, no passphrase needed, and no
// device-mapper state is touched). The header fields are not secret: they
// contain cipher parameters and identifiers, not key material.
//
// Two subprocesses are used for a LUKS2 header: the plain-text dump for
// Version and UUID (the UUID lives in the binary header area, not in the JSON
// metadata area), and --dump-json-metadata for the structured cipher/hash/
// keyslot parameters (the documented LUKS2 JSON schema — far more stable to
// parse than free-form text). A LUKS1 header needs only the text dump.
func DumpDetails(v *db.Vault) (*LUKSDetails, error) {
	out, err := exec.Command("cryptsetup", "luksDump", v.Path).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("luksDump: %s", strings.TrimSpace(string(out)))
	}
	text := string(out)

	d := &LUKSDetails{
		Version: dumpField(text, "Version"),
		UUID:    dumpField(text, "UUID"),
	}

	switch d.Version {
	case "2":
		if err := fillLUKS2(d, v.Path); err != nil {
			return nil, err
		}
		return d, nil
	case "1":
		parseLUKS1(d, text)
		return d, nil
	default:
		return nil, fmt.Errorf("unrecognized LUKS header version %q", d.Version)
	}
}

// dumpField extracts the value of a "Field:  value" line from luksDump text
// output. luksDump pads values with spaces, so the label match is anchored at
// line start and the value is trimmed.
func dumpField(text, label string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(label) + `:\s+(\S+)`)
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// fillLUKS2 parses cryptsetup's --dump-json-metadata output (the LUKS2 JSON
// metadata area) into d. The JSON schema is part of the on-disk LUKS2 format
// specification, so it is stable across cryptsetup versions.
func fillLUKS2(d *LUKSDetails, path string) error {
	out, err := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("luksDump --dump-json-metadata: %s", strings.TrimSpace(string(out)))
	}
	return parseLUKS2Metadata(d, out)
}

func parseLUKS2Metadata(d *LUKSDetails, raw []byte) error {
	var hdr struct {
		Keyslots map[string]struct {
			KeySize any `json:"key_size"`
			KDF     struct {
				Type string `json:"type"`
			} `json:"kdf"`
		} `json:"keyslots"`
		Digests map[string]struct {
			Hash string `json:"hash"`
		} `json:"digests"`
		Segments map[string]struct {
			Encryption string `json:"encryption"`
		} `json:"segments"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return fmt.Errorf("parse LUKS2 metadata: %w", err)
	}

	// Numeric map keys are strings in JSON; sort them numerically so slot 10
	// doesn't land before slot 2 and segment "0" (the data segment) is first.
	slotIdxs := sortedIndexes(hdr.Keyslots)
	for _, idx := range slotIdxs {
		ks := hdr.Keyslots[strconv.Itoa(idx)]
		d.KeySlots = append(d.KeySlots, KeySlot{
			Index:  idx,
			Type:   ks.KDF.Type,
			Status: "valid", // slots present in the metadata are valid by definition
		})
		if d.KeySizeBits == 0 {
			d.KeySizeBits = asInt(ks.KeySize) * 8
		}
	}

	for _, idx := range sortedIndexes(hdr.Digests) {
		d.Hash = hdr.Digests[strconv.Itoa(idx)].Hash
		break
	}
	for _, idx := range sortedIndexes(hdr.Segments) {
		d.Cipher = hdr.Segments[strconv.Itoa(idx)].Encryption
		break
	}
	return nil
}

// parseLUKS1 fills d from a classic LUKS1 text dump. The LUKS1 output format
// has been stable for many years, so line-oriented regex parsing is safe here.
func parseLUKS1(d *LUKSDetails, text string) {
	d.Hash = dumpField(text, "Hash spec")
	d.KeySizeBits = asInt(dumpField(text, "MK bits"))

	name, mode := dumpField(text, "Cipher name"), dumpField(text, "Cipher mode")
	d.Cipher = strings.TrimSuffix(name+"-"+mode, "-")

	for _, m := range regexp.MustCompile(`(?m)^Key Slot (\d+): (ENABLED|DISABLED)`).FindAllStringSubmatch(text, -1) {
		// LUKS1 always derives slot keys with PBKDF2.
		d.KeySlots = append(d.KeySlots, KeySlot{Index: asInt(m[1]), Type: "pbkdf2", Status: strings.ToLower(m[2])})
	}
}

func sortedIndexes[V any](m map[string]V) []int {
	idxs := make([]int, 0, len(m))
	for k := range m {
		if n, err := strconv.Atoi(k); err == nil {
			idxs = append(idxs, n)
		}
	}
	sort.Ints(idxs)
	return idxs
}

// asInt tolerates JSON values encoded as either numbers or numeric strings
// (the LUKS2 metadata area encodes most sizes as strings, key_size as a number).
func asInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		return atoiSafe(x)
	default:
		return 0
	}
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
