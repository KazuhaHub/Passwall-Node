package deployment

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/releaseid"
)

// ValidReleaseVersion is what the INSTALLER accepts, and the installer must keep
// refusing a product version. An installer that accepted one would render a
// download URL out of it, and a product version is not the path a release lives
// at — the tag is. Refusing is the direction that fails loudly: the operator is
// told the release source returned no usable version, rather than being handed
// a URL to somewhere that does not exist.
//
// This pins the behaviour so the rule can move to one implementation without the
// installer quietly widening. It is written as a table rather than a property
// because the interesting cases are the near misses.
func TestTheInstallerStillAcceptsOnlyLegacyVersions(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
		why   string
	}{
		{"v0.0.1-beta11", true, "the released shape"},
		{"v1.0.0", true, ""},
		{"v102.1.0", true, ""},
		{"v1.0.0-rc1", true, ""},
		{"v1.0.0-alpha.1", true, "a dotted prerelease"},
		// The product scheme, which the installer cannot place yet.
		{"4.0.0", false, "a product version is not a path a release lives at"},
		{"102.1.0", false, ""},
		{"0.1.0", false, ""},
		// Near misses that were already refused and must stay refused.
		{"v01.0.0", false, "leading zeroes"},
		{"v1.0", false, "three segments"},
		{"v1.0.0-alpha.01", false, "a redundant leading zero in a numeric prerelease segment"},
		{"v1.0.0+build", false, "build metadata"},
		{"1.0.0", false, ""},
		{"latest", false, ""},
		{"release/4.0.0", false, "a tag is not a version"},
		{"", false, ""},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := ValidReleaseVersion(tc.value); got != tc.ok {
				t.Errorf("ValidReleaseVersion(%q) = %v, want %v (%s)", tc.value, got, tc.ok, tc.why)
			}
		})
	}
}

// The rule is the legacy one, and there is one implementation of it. If these
// two ever disagree, the installer and the release tooling would be reading
// different rules about the same string — which is the class of defect this
// moved to prevent, not one it should reintroduce.
func TestTheInstallerRuleIsTheSharedLegacyRule(t *testing.T) {
	for _, value := range []string{
		"v1.0.0", "v0.0.1-beta11", "v1.0.0-rc1", "v01.0.0", "v1.0", "v1.0.0-alpha.01",
		"4.0.0", "102.1.0", "latest", "", "release/4.0.0",
	} {
		if got, want := ValidReleaseVersion(value), releaseid.ValidLegacyVersion(value); got != want {
			t.Errorf("ValidReleaseVersion(%q) = %v but releaseid.ValidLegacyVersion = %v", value, got, want)
		}
	}
}

// ValidReleaseVersion is the INSTALLER's rule, and the installer is the only
// thing that should read it. Everywhere else the question is "may this caller
// ask for this version", which is a different question with a different answer,
// and answering it with the installer's rule is what refused every product
// release: six call sites across the upgrade helper, the agent's own gates and
// the task decoder each asked the installer's question by accident.
//
// A defect that repeats in six places is not six mistakes. It is one rule used
// where it does not belong, so the check is on the scope rather than on the
// sites.
func TestOnlyInstallationCodeUsesTheInstallerRule(t *testing.T) {
	root := repoRoot(t)
	const installerPackage = "github.com/KazuhaHub/passwall-node/deployment"
	offenders := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "node_modules":
				return fs.SkipDir
			}
			// The package that defines the rule is where it belongs. A second
			// file importing it back would be a cycle, so in-package use is
			// the definition's own callers.
			if path == filepath.Join(root, "deployment") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		alias := ""
		for _, spec := range file.Imports {
			if strings.Trim(spec.Path.Value, `"`) != installerPackage {
				continue
			}
			if spec.Name != nil {
				alias = spec.Name.Name
			} else {
				alias = "deployment"
			}
		}
		if alias == "" {
			return nil
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ValidReleaseVersion" {
				return true
			}
			if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == alias {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				offenders = append(offenders, relative)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("these files ask the installer's question about a version a caller may request; use releaseid.ValidVersion instead:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
