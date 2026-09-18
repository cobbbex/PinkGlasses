// Package builtin is the manifest of the wordlists that ship with PinkGlasses:
// what the migrations register, what the image bundles, what the seeder loads
// into object storage at first boot. It has no dependencies, so the fetch tool
// that runs at image build time can compile it alone.
package builtin

import (
	"os"
	"path"
)

// List is one shipped wordlist.
type List struct {
	Name      string
	Kind      string // dns | dir | resolvers
	ObjectKey string // where it lives in object storage
	SourceURL string // where the image build fetches it from
}

// Lists mirrors the rows migrations 00009, 00011 and 00014 insert; a test keeps
// the two in step.
var Lists = []List{
	{Name: "assetnote best-dns-wordlist", Kind: "dns", ObjectKey: "wordlists/builtin/best-dns-wordlist.txt",
		SourceURL: "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"},
	{Name: "assetnote httparchive subdomains", Kind: "dns", ObjectKey: "wordlists/builtin/httparchive_subdomains.txt",
		SourceURL: "https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt"},
	{Name: "trickest public resolvers", Kind: "resolvers", ObjectKey: "wordlists/builtin/resolvers.txt",
		SourceURL: "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"},
	{Name: "seclists common web content", Kind: "dir", ObjectKey: "wordlists/builtin/dir-common.txt",
		SourceURL: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"},
	{Name: "seclists raft medium directories", Kind: "dir", ObjectKey: "wordlists/builtin/dir-raft-medium.txt",
		SourceURL: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"},
}

// DefaultBundleDir is where the control-plane image carries the lists.
const DefaultBundleDir = "/usr/share/pinkglasses/wordlists"

// BundleDir is the directory the seeder looks in, overridable for tests and
// unusual layouts.
func BundleDir() string {
	if d := os.Getenv("ASM_BUNDLED_WORDLISTS"); d != "" {
		return d
	}
	return DefaultBundleDir
}

// BundleFile is the bundled, gzip-compressed file for an object key.
func BundleFile(dir, objectKey string) string {
	return path.Join(dir, path.Base(objectKey)+".gz")
}
