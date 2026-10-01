package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

// THE UPDATER FINDS ITS OWN CONTAINER IN THE ROOT OF ITS /etc/hostname MOUNT.
// Docker serves that file from <data-root>/containers/<id>/hostname, so the ID is
// in the path, and only the tail is matched because the data root is wherever
// the host put it: on the root filesystem, on a NAS volume that is a filesystem
// of its own, on a dedicated disk (whose mountinfo root then starts at
// /containers), or under a rootless daemon's home directory. Anything else —
// no such mount, two of them, an ID that is not one, the right root at the wrong
// mount point, another runtime's layout — resolves nothing, and the handover
// stays off rather than guessing.
func TestParseMountinfoSelfID(t *testing.T) {
	const id = "6b1f4e0c9d2a87b3e5f40c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"
	for _, tc := range []struct {
		file string
		want string
	}{
		{"overlay2-var-lib-docker.txt", id},
		{"nas-volume1-docker.txt", id},
		{"nas-volume1-docker-same-fs.txt", id},
		{"data-root-own-filesystem.txt", id},
		{"rootless.txt", id},
		{"host.txt", ""},
		{"two-hostname-mounts.txt", ""},
		{"malformed-id.txt", ""},
		{"uppercase-id.txt", ""},
		{"wrong-mount-point.txt", ""},
		{"podman.txt", ""},
	} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "mountinfo", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseMountinfoSelfID(string(data))
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("parseMountinfoSelfID = (%q, %v), want an error and no ID", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseMountinfoSelfID = (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
	if _, err := parseMountinfoSelfID(""); err == nil {
		t.Fatal("an empty mountinfo resolved a container")
	}
}
