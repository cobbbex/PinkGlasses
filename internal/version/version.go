// Package version is the build's version, set at link time:
//
//	go build -ldflags "-X github.com/benlik386/pinkglasses/internal/version.Version=v1.2.3"
//
// The Dockerfiles pass the release tag (or the commit) through; a plain
// `go build` reports "dev".
package version

// Version is the release this binary was built from.
var Version = "dev"

// Commit is the source revision, when the build knows it.
var Commit = ""
