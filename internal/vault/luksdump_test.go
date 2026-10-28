package vault

import (
	"testing"
)

// luks1Dump is a classic LUKS1 luksDump output (trimmed to the lines the
// parser reads). The format has been stable across cryptsetup releases.
const luks1Dump = `LUKS header information for /vaults/private.img

Version:        1
Cipher name:    aes
Cipher mode:    xts-plain64
Hash spec:      sha256
Payload offset: 4096
MK bits:        512
MK digest:      aa bb
MK salt:        cc dd
MK iterations:  12345
UUID:           3f9d1c2e-8a47-4b8e-9c21-7d6e5f4a3b2c

Key Slot 0: ENABLED
	Iterations:         12345
	Salt:               cc
Key Slot 1: DISABLED
`

// luks2Dump is the text part of a LUKS2 luksDump. Version and UUID are the
// only fields read from the text dump for LUKS2 — everything else comes from
// the JSON metadata area.
const luks2Dump = `LUKS header information
Version:        2
Epoch:          4
Metadata area:  16384 [bytes]
Keyslots area:  16744448 [bytes]
UUID:           6a2f5e10-94c3-4d7a-8f21-0b3c9e8d7a1f
Label:          (no label)
Subsystem:      (no label)
Offset:         16777216 [bytes]
Requirements:   (no requirements)

Keyslot 0: luks2
	Status:        enabled
`

// luks2Metadata is a representative --dump-json-metadata payload following
// the LUKS2 on-disk JSON schema (key_size is a number, sizes are strings).
const luks2Metadata = `{
  "keyslots": {
    "1": {
      "type": "luks2",
      "key_size": 64,
      "kdf": {"type": "argon2id", "time": 7, "memory": 1048576, "cpus": 4},
      "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"}
    },
    "0": {
      "type": "luks2",
      "key_size": 64,
      "kdf": {"type": "argon2id", "time": 7, "memory": 1048576, "cpus": 4},
      "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"}
    }
  },
  "tokens": {},
  "digests": {
    "0": {"type": "pbkdf2", "keyslots": ["0", "1"], "segments": ["0"], "hash": "sha256", "iterations": 1000}
  },
  "segments": {
    "0": {"type": "crypt", "offset": "16777216", "size": "dynamic", "encryption": "aes-xts-plain64", "sector_size": 512}
  },
  "config": {"json_size": "12288", "keyslots_size": "16744448"}
}`

func TestParseLUKS1Dump(t *testing.T) {
	d := &LUKSDetails{Version: dumpField(luks1Dump, "Version"), UUID: dumpField(luks1Dump, "UUID")}
	if d.Version != "1" || d.UUID != "3f9d1c2e-8a47-4b8e-9c21-7d6e5f4a3b2c" {
		t.Fatalf("version/uuid = %q/%q", d.Version, d.UUID)
	}
	parseLUKS1(d, luks1Dump)

	if d.Cipher != "aes-xts-plain64" {
		t.Errorf("cipher = %q, want aes-xts-plain64", d.Cipher)
	}
	if d.Hash != "sha256" {
		t.Errorf("hash = %q, want sha256", d.Hash)
	}
	if d.KeySizeBits != 512 {
		t.Errorf("key_size_bits = %d, want 512", d.KeySizeBits)
	}
	if len(d.KeySlots) != 2 {
		t.Fatalf("got %d keyslots, want 2", len(d.KeySlots))
	}
	if d.KeySlots[0] != (KeySlot{Index: 0, Type: "pbkdf2", Status: "enabled"}) {
		t.Errorf("slot 0 = %+v", d.KeySlots[0])
	}
	if d.KeySlots[1] != (KeySlot{Index: 1, Type: "pbkdf2", Status: "disabled"}) {
		t.Errorf("slot 1 = %+v", d.KeySlots[1])
	}
}

func TestParseLUKS2Metadata(t *testing.T) {
	d := &LUKSDetails{Version: "2", UUID: dumpField(luks2Dump, "UUID")}
	if err := parseLUKS2Metadata(d, []byte(luks2Metadata)); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if d.Cipher != "aes-xts-plain64" {
		t.Errorf("cipher = %q, want aes-xts-plain64", d.Cipher)
	}
	if d.Hash != "sha256" {
		t.Errorf("hash = %q, want sha256", d.Hash)
	}
	// key_size 64 bytes must be converted to bits.
	if d.KeySizeBits != 512 {
		t.Errorf("key_size_bits = %d, want 512", d.KeySizeBits)
	}
	// Slots must be sorted numerically despite JSON map ordering.
	if len(d.KeySlots) != 2 {
		t.Fatalf("got %d keyslots, want 2", len(d.KeySlots))
	}
	if d.KeySlots[0].Index != 0 || d.KeySlots[1].Index != 1 {
		t.Errorf("keyslot order = %d,%d, want 0,1", d.KeySlots[0].Index, d.KeySlots[1].Index)
	}
	if d.KeySlots[0].Type != "argon2id" || d.KeySlots[0].Status != "valid" {
		t.Errorf("slot 0 = %+v, want type argon2id status valid", d.KeySlots[0])
	}
	if d.UUID != "6a2f5e10-94c3-4d7a-8f21-0b3c9e8d7a1f" {
		t.Errorf("uuid = %q", d.UUID)
	}
}

// Key slots must sort numerically: 10 after 2.
func TestParseLUKS2MetadataSlotOrdering(t *testing.T) {
	meta := `{
  "keyslots": {
    "10": {"type": "luks2", "key_size": 32, "kdf": {"type": "pbkdf2"}},
    "2":  {"type": "luks2", "key_size": 32, "kdf": {"type": "pbkdf2"}}
  },
  "digests": {},
  "segments": {"0": {"type": "crypt", "encryption": "aes-xts-plain64"}}
}`
	d := &LUKSDetails{Version: "2"}
	if err := parseLUKS2Metadata(d, []byte(meta)); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(d.KeySlots) != 2 || d.KeySlots[0].Index != 2 || d.KeySlots[1].Index != 10 {
		t.Errorf("keyslot order = %+v, want [2 10]", d.KeySlots)
	}
}

func TestParseLUKS2MetadataInvalidJSON(t *testing.T) {
	d := &LUKSDetails{Version: "2"}
	if err := parseLUKS2Metadata(d, []byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDumpField(t *testing.T) {
	if got := dumpField(luks2Dump, "UUID"); got != "6a2f5e10-94c3-4d7a-8f21-0b3c9e8d7a1f" {
		t.Errorf("UUID = %q", got)
	}
	if got := dumpField(luks2Dump, "Missing"); got != "" {
		t.Errorf("missing field = %q, want \"\"", got)
	}
}
