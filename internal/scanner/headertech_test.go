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
