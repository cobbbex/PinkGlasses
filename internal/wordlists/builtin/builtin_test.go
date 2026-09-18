package builtin

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every builtin the migrations insert is in the manifest with the same object
// key and source URL, and nothing is in the manifest the migrations do not
// register — otherwise the image would bundle a list the registry never asks
// for, or register one the bundle lacks.
func TestManifestMatchesMigrations(t *testing.T) {
	files, _ := filepath.Glob("../../../migrations/*.sql")
	if len(files) == 0 {
		t.Skip("migrations not found")
	}
	row := regexp.MustCompile(`\('([^']+)',\s*'(dns|dir|resolvers)',\s*'(wordlists/builtin/[^']+)',\s*\n?\s*'(https?://[^']+)'`)
	seen := map[string]List{}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, m := range row.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = List{Name: m[1], Kind: m[2], ObjectKey: m[3], SourceURL: m[4]}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no builtin rows found in the migrations; the pattern is stale")
	}
	for _, l := range Lists {
		got, ok := seen[l.Name]
		if !ok {
			t.Errorf("%q is in the manifest but no migration registers it", l.Name)
			continue
		}
		if got != l {
			t.Errorf("%q differs: manifest %+v, migration %+v", l.Name, l, got)
		}
		delete(seen, l.Name)
	}
	for name := range seen {
		t.Errorf("%q is registered by a migration but missing from the manifest", name)
	}
}
