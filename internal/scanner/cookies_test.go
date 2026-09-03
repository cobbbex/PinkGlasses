package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The name is the fingerprint; the value is a session token and must never be
// recorded. Cisco ASA WebVPN is the motivating case: its cookie names identify
// the product where the banner and title say nothing useful.
func TestCookieNamesFromResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure")
		w.Header().Add("Set-Cookie", "webvpnlogin=1; secure; httponly")
		w.Header().Add("Set-Cookie", "webvpnLang=en; path=/")
		w.Header().Add("Set-Cookie", "webvpn=dup-name-different-value; path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got := cookieNamesFromResponse(resp)
	want := []string{"webvpn", "webvpnLang", "webvpnlogin"} // sorted, deduped
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("cookieNamesFromResponse = %v, want %v", got, want)
	}
	for _, n := range got {
		if strings.Contains(n, "=") || strings.Contains(n, "dup-name-different-value") {
			t.Errorf("a cookie value leaked into the stored names: %q", n)
		}
	}
}

// httpx flattens every Set-Cookie into one string, so the names have to be
// recovered from it. The trap is the comma inside an expires date, which is not
// a cookie boundary, and the attributes after a semicolon, which are not names.
func TestCookieNamesFromHeader(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"single", "webvpn=abc; path=/; secure", "webvpn"},
		{"expires comma is not a boundary",
			"__Secure-STRP=xyz; expires=Thu, 03-Sep-2026 10:10:50 GMT; path=/; domain=.example.com",
			"__Secure-STRP"},
		{"several cookies",
			"webvpn=a; path=/, webvpnlogin=b; secure, webvpnLang=en",
			"webvpn,webvpnlogin,webvpnLang"},
		{"f5 and citrix together",
			"BIGipServerpool_web=1234.5678.0000; path=/, NSC_wt_mfi=abc; secure",
			"BIGipServerpool_web,NSC_wt_mfi"},
		{"attributes are not names", "a=1; Path=/; HttpOnly; SameSite=Lax", "a"},
		{"empty", "", ""},
		{"whitespace", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cookieNamesFromHeader(c.in)
			// compare as sets, since the result is sorted
			var want []string
			if c.want != "" {
				want = strings.Split(c.want, ",")
			}
			if len(got) != len(want) {
				t.Fatalf("cookieNamesFromHeader(%q) = %v, want %v", c.in, got, want)
			}
			seen := map[string]bool{}
			for _, g := range got {
				seen[g] = true
			}
			for _, w := range want {
				if !seen[w] {
					t.Errorf("missing %q in %v", w, got)
				}
			}
			for _, g := range got {
				if strings.ContainsAny(g, "=;,") {
					t.Errorf("%q is not a bare cookie name", g)
				}
			}
		})
	}
}

func TestHeaderField(t *testing.T) {
	row := map[string]any{"header": map[string]any{"set_cookie": "a=1", "server": "nginx"}}
	if got := headerField(row, "set_cookie"); got != "a=1" {
		t.Errorf("headerField = %q", got)
	}
	if got := headerField(map[string]any{}, "set_cookie"); got != "" {
		t.Errorf("missing header should be empty, got %q", got)
	}
}
