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

// ValidReleaseVersion is what the INSTALLER accepts, and what it accepts is the
// project's version — the same rule a caller asking for a release is held to.
//
// IT USED TO ACCEPT ONLY THE LEGACY SHAPE, and refusing the product form was the
// point: the installer built a download URL out of the version, so a version that
// was not also the path a release lives at produced a URL to somewhere that does
// not exist. The template takes the tag separately now, so the version is a
// version, and the direction of the refusal has reversed: the legacy shape is the
// string this installer cannot place.
func TestTheInstallerAcceptsTheProjectsVersions(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
		why   string
	}{
		{"4.0.0", true, "the released shape"},
		{"102.1.0", true, ""},
		{"4.0.0.1", true, "the optional build component"},
		{"1.0.0", true, ""},
		// The legacy shape, which no longer names anything the installer places.
		{"v0.0.1-beta11", false, "the scheme this project stopped publishing"},
		{"v1.0.0", false, ""},
		{"v102.1.0", false, ""},
		{"v1.0.0-rc1", false, ""},
		// Near misses that were already refused and must stay refused.
		{"01.0.0", false, "leading zeroes"},
		{"4.0", false, "three segments"},
		{"4.0.0+build", false, "build metadata"},
		{"0.1.0", false, "the product line starts at one"},
		{"4.0.0.0", false, "a literal zero build is another spelling of three segments"},
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

// The rule is shared, and there is one implementation of it. If these two ever
// disagree, the installer and the callers that judge a requested version would be
// reading different rules about the same string — which is the class of defect
// this consolidates against.
func TestTheInstallerRuleIsTheSharedRule(t *testing.T) {
	for _, value := range []string{
		"4.0.0", "4.0.0.1", "102.1.0", "01.0.0", "4.0", "4.0.0+build", "0.1.0",
		"v1.0.0", "v0.0.1-beta11", "v1.0.0-rc1", "latest", "", "release/4.0.0",
	} {
		if got, want := ValidReleaseVersion(value), releaseid.ValidVersion(value); got != want {
			t.Errorf("ValidReleaseVersion(%q) = %v but releaseid.ValidVersion = %v", value, got, want)
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
