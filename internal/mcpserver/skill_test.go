package mcpserver

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// The skill's tool reference is generated from the tool set, so every tool
// the server exposes is documented, and the archive unpacks into one folder
// with SKILL.md at its root.
func TestSkillCoversEveryTool(t *testing.T) {
	files := SkillFiles(Options{AllowDeleteCompany: true})
	ref := files["pinkglasses/reference/tools.md"]
	for _, tl := range Tools(Options{AllowDeleteCompany: true}) {
		if !strings.Contains(ref, "## "+tl.Name+"\n") {
			t.Errorf("tool %s is missing from the skill's reference", tl.Name)
		}
	}
	skill := files["pinkglasses/SKILL.md"]
	if !strings.HasPrefix(skill, "---\nname: pinkglasses\n") {
		t.Errorf("SKILL.md must start with its front matter, got %q", skill[:40])
	}
	data, err := SkillZip(Options{})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range zr.File {
		seen[f.Name] = true
		if !strings.HasPrefix(f.Name, "pinkglasses/") {
			t.Errorf("file outside the skill folder: %s", f.Name)
		}
	}
	for _, want := range []string{"pinkglasses/SKILL.md", "pinkglasses/reference/tools.md",
		"pinkglasses/reference/search-query-language.md", "pinkglasses/reference/scanning.md"} {
		if !seen[want] {
			t.Errorf("zip lacks %s", want)
		}
	}
	// delete_company is documented only when the server offers it.
	if strings.Contains(SkillFiles(Options{})["pinkglasses/reference/tools.md"], "## delete_company") {
		t.Error("delete_company documented although the server does not offer it")
	}
}
