package httpapi

import "testing"

func TestValidResolver(t *testing.T) {
	good := []string{
		"1.1.1.1",
		"8.8.8.8:53",
		"208.67.222.222:5353",
		"2606:4700:4700::1111",
		"[2606:4700:4700::1111]:53",
	}
	for _, v := range good {
		if err := validResolver(v); err != nil {
			t.Errorf("rejected valid resolver %q: %v", v, err)
		}
	}

	bad := []string{
		"not-an-ip",
		"999.1.1.1",
		"1.1.1.1:99999",
		"1.1.1.1:0",
		"1.1.1.1:http",
		"example.com", // hostnames are not resolvers here
		"1.1.1.1/24",  // a prefix is not a resolver
		"",            // handled by the caller, but must not pass
	}
	for _, v := range bad {
		if err := validResolver(v); err == nil {
			t.Errorf("accepted invalid resolver %q", v)
		}
	}
}

func TestNormalizeListResolvers(t *testing.T) {
	in := "# my resolvers\n1.1.1.1\n\n  8.8.8.8  \n1.1.1.1\n9.9.9.9\r\n"
	entries, problems := normalizeList(in, "resolvers")

	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries %v, want %d", len(entries), entries, len(want))
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, entries[i], want[i])
		}
	}
}

func TestNormalizeListReportsBadLinesWithNumbers(t *testing.T) {
	in := "1.1.1.1\nnot-an-ip\n8.8.8.8\n999.1.1.1\n"
	entries, problems := normalizeList(in, "resolvers")

	if len(entries) != 2 {
		t.Errorf("valid entries kept = %d, want 2 (%v)", len(entries), entries)
	}
	if len(problems) != 2 {
		t.Fatalf("problems = %d, want 2: %v", len(problems), problems)
	}
	// The line number must point at the original input, not the filtered set,
	// or the message sends the user to the wrong line.
	if got := problems[0]; got[:7] != "line 2:" {
		t.Errorf("first problem = %q, want it to start with \"line 2:\"", got)
	}
	if got := problems[1]; got[:7] != "line 4:" {
		t.Errorf("second problem = %q, want it to start with \"line 4:\"", got)
	}
}

func TestNormalizeListWordlistSkipsIPValidation(t *testing.T) {
	// A subdomain wordlist is arbitrary words; only resolvers are IP-checked.
	in := "www\nmail\n# comment\nwww\napi-v2\n"
	entries, problems := normalizeList(in, "dns")

	if len(problems) != 0 {
		t.Fatalf("wordlist entries should not be IP-validated, got: %v", problems)
	}
	// www, mail, api-v2 — the comment and the repeated "www" are dropped.
	if len(entries) != 3 {
		t.Errorf("entries = %v, want 3 after dropping the comment and the duplicate", entries)
	}
}

func TestNormalizeListCapsProblemCount(t *testing.T) {
	// A wholly invalid paste must not return a wall of errors.
	in := ""
	for i := 0; i < 100; i++ {
		in += "nope\n"
	}
	_, problems := normalizeList(in, "resolvers")
	if len(problems) > 20 {
		t.Errorf("problems = %d, want at most 20", len(problems))
	}
	if len(problems) == 0 {
		t.Error("expected problems for an entirely invalid list")
	}
}
