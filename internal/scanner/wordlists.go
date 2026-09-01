package scanner

import "os"

// Wordlist paths, overridable per worker. Defaults match the paths baked into
// the worker image (see deploy/Dockerfile.worker).
func wordlistDNS() string {
	return envOr("ASM_WORDLIST_DNS", "/usr/share/asm/wordlists/dns-subdomains.txt")
}
func wordlistDir() string {
	return envOr("ASM_WORDLIST_DIR", "/usr/share/asm/wordlists/dir-common.txt")
}
func resolversFile() string { return envOr("ASM_RESOLVERS", "/usr/share/asm/wordlists/resolvers.txt") }

// fileExists reports whether a path is present and non-empty, so a stage can
// skip cleanly when its wordlist was not shipped.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
