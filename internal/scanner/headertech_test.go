package scanner

import (
	"net/http"
	"testing"
)

// A site that redirects with "X-Redirect-By: WordPress" is a WordPress site,
// whatever the page fingerprint made of the redirect. This is the case that
// prompted the rules: three hosts carried the header and none the tag.
func TestTechFromHeaders(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
		want    []techHint
	}{
		{"wordpress redirect", http.Header{"X-Redirect-By": {"WordPress"}},
			[]techHint{{"WordPress", "", 85}}},
		{"plugin redirect names both", http.Header{"X-Redirect-By": {"Yoast SEO"}},
			[]techHint{{"WordPress", "", 85}, {"Yoast SEO", "", 70}}},
		{"rest api link", http.Header{"Link": {`<https://example.org/wp-json/>; rel="https://api.w.org/"`}},
			[]techHint{{"WordPress", "", 85}}},
		{"generator with version and url", http.Header{"X-Generator": {"Drupal 10 (https://www.drupal.org)"}},
			[]techHint{{"Drupal", "10", 85}}},
		{"generator with tagline", http.Header{"X-Generator": {"Joomla! - Open Source Content Management"}},
			[]techHint{{"Joomla!", "", 85}}},
		{"powered by, two products", http.Header{"X-Powered-By": {"PHP/8.1.2, ASP.NET"}},
			[]techHint{{"PHP", "8.1.2", 75}, {"ASP.NET", "", 75}}},
		{"versioned hint upgrades a versionless one",
			http.Header{"X-Redirect-By": {"WordPress"}, "X-Generator": {"WordPress 6.4.2"}},
			[]techHint{{"WordPress", "6.4.2", 85}}},
		{"nothing telling", http.Header{"Server": {"nginx"}, "Content-Type": {"text/html"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := techFromHeaders(c.headers.Get)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("hint %d: got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// httpx lower-cases header names and swaps '-' for '_' in its JSON; the
// rules are written against the canonical names, so the lookup maps them.
func TestHTTPXHeaderLookup(t *testing.T) {
	row := map[string]any{"header": map[string]any{"x_redirect_by": "WordPress", "content_type": "text/html"}}
	got := techFromHeaders(httpxHeader(row))
	if len(got) != 1 || got[0].Name != "WordPress" {
		t.Fatalf("got %+v, want WordPress", got)
	}
}

// A technology the page fingerprint already named is not added again, whatever
// its version — the store keeps one row per name and precision, and the
// fingerprint's is the fuller sighting.
func TestTechObservationsSkipNamed(t *testing.T) {
	hints := []techHint{{"WordPress", "", 85}, {"PHP", "8.1", 75}}
	obs := techObservations("1.2.3.4", 443, "example.org", hints, map[string]bool{"wordpress": true})
	if len(obs) != 1 || obs[0].TechName != "PHP" || obs[0].TechVersion != "8.1" || obs[0].Host != "example.org" {
		t.Fatalf("got %+v", obs)
	}
}

// Apache with mod_php names PHP only as the second token of Server; the
// product parse keeps the first, so the module rule is what records PHP.
func TestServerModules(t *testing.T) {
	got := techFromHeaders(http.Header{"Server": {"Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.24 OpenSSL/1.1.1f"}}.Get)
	want := []techHint{{"PHP", "7.4.3-4ubuntu2.24", 85}, {"OpenSSL", "1.1.1f", 70}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hint %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := techFromHeaders(http.Header{"Server": {"nginx/1.24.0"}}.Get); len(got) != 0 {
		t.Errorf("a lone server product is the service's, not a module: %+v", got)
	}
	// X-Powered-By and Server agreeing is one PHP, not two.
	both := techFromHeaders(http.Header{"X-Powered-By": {"PHP/8.2.20"}, "Server": {"Apache/2.4.62 PHP/8.2.20"}}.Get)
	if len(both) != 1 || both[0].Name != "PHP" || both[0].Version != "8.2.20" {
		t.Errorf("got %+v, want one PHP 8.2.20", both)
	}
}

func TestTechFromCookies(t *testing.T) {
	cases := []struct {
		name    string
		cookies []string
		want    []techHint
	}{
		{"php session", []string{"PHPSESSID"}, []techHint{{"PHP", "", 75}}},
		{"laravel", []string{"XSRF-TOKEN", "laravel_session"},
			[]techHint{{"Laravel", "", 90}, {"PHP", "", 80}}},
		{"renamed laravel session", []string{"XSRF-TOKEN", "acme_portal_session"},
			[]techHint{{"Laravel", "", 75}, {"PHP", "", 70}}},
		{"codeigniter", []string{"ci_session"}, []techHint{{"CodeIgniter", "", 85}, {"PHP", "", 80}}},
		{"symfony profiler", []string{"sf_redirect", "PHPSESSID"},
			[]techHint{{"Symfony", "", 85}, {"PHP", "", 75}}},
		{"xsrf alone is not laravel", []string{"XSRF-TOKEN"}, nil},
		{"nothing telling", []string{"JSESSIONID", "_ga"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := techFromCookies(c.cookies)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("hint %d: got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}
