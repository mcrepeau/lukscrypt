package vault

import "testing"

func slot(idx int, status string) KeySlot {
	return KeySlot{Index: idx, Type: "argon2id", Status: status}
}

func TestValidateKillSlot(t *testing.T) {
	tests := []struct {
		name    string
		slots   []KeySlot
		target  int
		wantErr bool
	}{
		{"normal remove — one of several LUKS2 slots",
			[]KeySlot{slot(0, "valid"), slot(1, "valid")}, 1, false},
		{"normal remove — one of several LUKS1 slots",
			[]KeySlot{slot(0, "enabled"), slot(1, "enabled")}, 0, false},
		{"last valid slot is protected",
			[]KeySlot{slot(0, "valid")}, 0, true},
		{"last enabled LUKS1 slot is protected",
			[]KeySlot{slot(0, "enabled")}, 0, true},
		// Removing the only enabled LUKS1 slot while a disabled one exists
		// must still be refused: disabled slots hold no usable copy.
		{"only enabled slot with a disabled sibling is protected",
			[]KeySlot{slot(0, "enabled"), slot(1, "disabled")}, 0, true},
		{"target slot not present",
			[]KeySlot{slot(0, "valid"), slot(1, "valid")}, 5, true},
		{"target slot disabled (LUKS1)",
			[]KeySlot{slot(0, "enabled"), slot(1, "disabled")}, 1, true},
		{"no slots at all",
			nil, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &LUKSDetails{Version: "2", KeySlots: tt.slots}
			err := ValidateKillSlot(d, tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKillSlot(%d) = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}
