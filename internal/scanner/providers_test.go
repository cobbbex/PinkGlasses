package scanner

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestProviderEnvVarsAreDelivered checks that every variable providerSources
// reads is actually handed to the worker by docker-compose, and offered in
// .env.example for somebody to paste a key into.
//
// The three lists are written in three places and each is useless without the
// others: a key in .env that compose does not forward never reaches the worker,
// and a variable compose forwards that providerSources does not read is
// delivered and ignored. Neither produces an error — just fewer subdomains.
func TestProviderEnvVarsAreDelivered(t *testing.T) {
	want := map[string]bool{}
	for _, ps := range providerSources {
		want[ps.env] = true
		if ps.env2 != "" {
			want[ps.env2] = true
		}
	}

	compose := readRepoFile(t, "../../docker-compose.yml")
	example := readRepoFile(t, "../../.env.example")

	for v := range want {
		if !regexp.MustCompile(`(?m)^\s*` + v + `:`).MatchString(compose) {
			t.Errorf("%s is read by providerSources but docker-compose.yml does not "+
				"pass it to the worker, so a key set in .env never arrives", v)
		}
		if !regexp.MustCompile(`(?m)^` + v + `=`).MatchString(example) {
			t.Errorf("%s is read by providerSources but .env.example does not offer it, "+
				"so nobody knows it exists", v)
		}
	}

	// And the other direction: a variable delivered but never read.
	for _, v := range regexp.MustCompile(`(?m)^([A-Z0-9_]+)=`).FindAllStringSubmatch(example, -1) {
		name := v[1]
		if strings.HasPrefix(name, "ASM_") || !looksLikeProviderKey(name) {
			continue
		}
		if !want[name] {
			t.Errorf(".env.example offers %s but providerSources never reads it, so a "+
				"key pasted there is silently ignored", name)
		}
	}
}

func looksLikeProviderKey(n string) bool {
	for _, suffix := range []string{"_API_KEY", "_TOKEN", "_EMAIL", "_HOST", "_API_SECRET", "_API_ID"} {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// TestProviderSourcesAreUnique guards against a duplicated source name, which
// would render the same YAML key twice and let the second silently win.
func TestProviderSourcesAreUnique(t *testing.T) {
	seenSource, seenEnv := map[string]bool{}, map[string]bool{}
	for _, ps := range providerSources {
		if seenSource[ps.source] {
			t.Errorf("source %q appears twice", ps.source)
		}
		seenSource[ps.source] = true
		for _, e := range []string{ps.env, ps.env2} {
			if e == "" {
				continue
			}
			if seenEnv[e] {
				t.Errorf("env var %q is used by two sources", e)
			}
			seenEnv[e] = true
		}
	}
}

// TestWriteProviderConfigSkipsHalfCredentials checks that a two-part source with
// only one half set is left out entirely. Writing it would produce a source that
// looks configured and returns nothing.
func TestWriteProviderConfigSkipsHalfCredentials(t *testing.T) {
	for _, v := range []string{"CENSYS_API_ID", "CENSYS_API_SECRET", "SHODAN_API_KEY", "FOFA_EMAIL", "FOFA_API_KEY"} {
		t.Setenv(v, "")
	}
	t.Setenv("CENSYS_API_ID", "only-the-id")
	t.Setenv("SHODAN_API_KEY", "a-real-key")

	dir := t.TempDir()
	path, sources, err := WriteProviderConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0] != "shodan" {
		t.Fatalf("configured %v, want just [shodan]", sources)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "censys") {
		t.Error("censys was written with only half its credentials")
	}
	if !strings.Contains(string(body), "a-real-key") {
		t.Error("the shodan key did not make it into the config")
	}
	// The file holds credentials and must not be world-readable.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("provider config is mode %v, want 0600", st.Mode().Perm())
	}
}

func readRepoFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("cannot read %s: %v", p, err)
	}
	return string(b)
}

// TestEnvExampleHasNoInlineComments guards a trap that cost a real debugging
// round: a .env file has no inline comments, so
//
//	SHODAN_API_KEY=            # shodan
//
// sets the key to "            # shodan". Written that way, every source came up
// "configured" from a file of blanks and the worker sent a comment to 37 APIs as
// though it were a credential. Annotate above the line, never after it.
func TestEnvExampleHasNoInlineComments(t *testing.T) {
	inline := regexp.MustCompile(`(?m)^([A-Z0-9_]+)=(.*#.*)$`)
	for _, m := range inline.FindAllStringSubmatch(readRepoFile(t, "../../.env.example"), -1) {
		t.Errorf("%s has an inline comment: %q. A .env value runs to end of line, "+
			"so this would be part of the credential.", m[1], m[2])
	}
}
