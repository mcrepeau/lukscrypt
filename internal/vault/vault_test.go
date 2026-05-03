package vault

import "testing"

// realMounts is a representative /proc/mounts snapshot used across tests.
// Format: <device> <mountpoint> <fstype> <options> <dump> <pass>
var realMounts = []byte(
	"sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\n" +
		"proc /proc proc rw,nosuid,nodev,noexec 0 0\n" +
		"/dev/mapper/myvault /mnt/myvault ext4 rw,relatime 0 0\n" +
		"/dev/mapper/data /mnt/data ext4 rw,relatime 0 0\n",
)

func TestMountedIn(t *testing.T) {
	tests := []struct {
		name       string
		mountPoint string
		mounts     []byte
		want       bool
	}{
		// present
		{"first vault", "/mnt/myvault", realMounts, true},
		{"second vault", "/mnt/data", realMounts, true},

		// absent
		{"not mounted", "/mnt/other", realMounts, false},
		{"nil mounts", "/mnt/myvault", nil, false},
		{"empty mounts", "/mnt/myvault", []byte{}, false},

		// prefix safety: "/mnt/data" must not match when only "/mnt/data-2" is mounted
		{
			name:       "prefix not matched by longer name",
			mountPoint: "/mnt/data",
			mounts:     []byte("/dev/mapper/x /mnt/data-2 ext4 rw 0 0\n"),
			want:       false,
		},
		// suffix safety: "/mnt/data-2" must not match when only "/mnt/data" is mounted
		{
			name:       "longer name not matched by prefix",
			mountPoint: "/mnt/data-2",
			mounts:     []byte("/dev/mapper/x /mnt/data ext4 rw 0 0\n"),
			want:       false,
		},
		// partial string match that would pass without space delimiters
		{
			name:       "substring of mount point not matched",
			mountPoint: "/mnt/my",
			mounts:     realMounts,
			want:       false,
		},
		{
			name:       "superset of mount point not matched",
			mountPoint: "/mnt/myvaultextra",
			mounts:     realMounts,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mountedIn(tt.mountPoint, tt.mounts); got != tt.want {
				t.Errorf("mountedIn(%q) = %v, want %v", tt.mountPoint, got, tt.want)
			}
		})
	}
}
