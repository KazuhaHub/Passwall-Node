package upgrade

import "testing"

func TestDockerHostPathOverlapUsesLinuxSeparators(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		want       bool
	}{
		{"parent", "/srv/data", "/srv/data/state.db", true},
		{"cleaned-parent", "/srv/node/../data/", "/srv/data//state.db", true},
		{"root", "/", "/srv/data", true},
		{"prefix-only", "/srv/data", "/srv/database", false},
		{"sibling", "/srv/control", "/srv/data", false},
		{"empty-tmpfs", "", "/srv/data", false},
		{"literal-backslash-is-not-a-linux-separator", `/srv/data\state.db`, "/srv/data", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if pathsOverlap(tc.a, tc.b) != tc.want || pathsOverlap(tc.b, tc.a) != tc.want {
				t.Fatalf("Linux path overlap disagreed with expected containment %t", tc.want)
			}
		})
	}
}
