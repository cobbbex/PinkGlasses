package scanner

import (
	"strings"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// Response headers name the software behind a site more often than the page
// does. WordPress core sends X-Redirect-By on every redirect it issues and a
// Link to its REST API on every page; Drupal, Shopify, ASP.NET, Magento and
// the rest each leave a header of their own. The page fingerprint (httpx's
// wappalyzer) misses these whenever it gets a redirect, an error page or a
// front page that is not the application — which is exactly when a site was
// seen to carry "X-Redirect-By: WordPress" and no WordPress tag.
//
// Server is left to the stages that already parse it into a product.

type techHint struct {
	Name, Version string
	Confidence    int
}

// headerTechRules maps a header to what its presence, or its value, says.
// Each rule may return no hint (value did not match) or several (a plugin
// header names the platform and the plugin).
var headerTechRules = []struct {
	Header string
	Hints  func(value string) []techHint
}{
	// WordPress core sets it on redirects; the value names what asked for
	// the redirect — "WordPress" itself or a plugin such as "Yoast SEO".
	{"X-Redirect-By", func(v string) []techHint {
		hs := []techHint{{"WordPress", "", 85}}
		if !strings.EqualFold(v, "WordPress") && v != "" {
			hs = append(hs, techHint{v, "", 70})
		}
		return hs
	}},
	{"Link", func(v string) []techHint {
		if strings.Contains(v, "api.w.org") || strings.Contains(v, "/wp-json/") {
			return []techHint{{"WordPress", "", 85}}
		}
		return nil
	}},
	{"X-Pingback", func(v string) []techHint {
		if strings.Contains(v, "xmlrpc.php") {
			return []techHint{{"WordPress", "", 80}}
		}
		return nil
	}},
	// "Drupal 10 (https://www.drupal.org)", "WordPress 6.4.2",
	// "Joomla! - Open Source Content Management".
	{"X-Generator", func(v string) []techHint {
		name, version := generatorNameVersion(v)
		if name == "" {
			return nil
		}
		return []techHint{{name, version, 85}}
	}},
	{"X-Drupal-Cache", constant("Drupal", 80)},
	{"X-Drupal-Dynamic-Cache", constant("Drupal", 80)},
	// "PHP/8.1.2", "ASP.NET", "Express", "Next.js"; sometimes several,
	// comma-separated.
	{"X-Powered-By", func(v string) []techHint {
		var hs []techHint
		for _, part := range strings.Split(v, ",") {
			name, version := splitProductVersion(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			if strings.EqualFold(name, "PleskLin") || strings.EqualFold(name, "PleskWin") {
				name = "Plesk"
			}
			hs = append(hs, techHint{name, version, 75})
		}
		return hs
	}},
	{"X-AspNet-Version", func(v string) []techHint { return []techHint{{"ASP.NET", v, 85}} }},
	{"X-AspNetMvc-Version", func(v string) []techHint { return []techHint{{"ASP.NET MVC", v, 85}} }},
	{"X-Shopify-Stage", constant("Shopify", 85)},
	{"X-ShopId", constant("Shopify", 80)},
	{"X-Magento-Tags", constant("Magento", 85)},
	{"X-Magento-Cache-Debug", constant("Magento", 85)},
	{"X-Wix-Request-Id", constant("Wix", 85)},
	{"X-Varnish", constant("Varnish", 80)},
	{"X-Litespeed-Cache", constant("LiteSpeed Cache", 80)},
	{"X-Nextjs-Cache", constant("Next.js", 80)},
	{"X-Vercel-Id", constant("Vercel", 80)},
	{"X-Github-Request-Id", constant("GitHub Pages", 80)},
	{"X-Amz-Cf-Id", constant("Amazon CloudFront", 80)},
	{"CF-Ray", constant("Cloudflare", 80)},
	{"X-Sucuri-ID", constant("Sucuri", 80)},
	{"X-Akamai-Transformed", constant("Akamai", 80)},
}

func constant(name string, confidence int) func(string) []techHint {
	return func(string) []techHint { return []techHint{{name, "", confidence}} }
}

// generatorNameVersion reads an X-Generator value: the parenthesised URL and
// any " - tagline" go, then a trailing version token splits off the name.
func generatorNameVersion(v string) (name, version string) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "("); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if i := strings.Index(v, " - "); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" {
		return "", ""
	}
	fields := strings.Fields(v)
	last := fields[len(fields)-1]
	if len(fields) > 1 && last[0] >= '0' && last[0] <= '9' {
		return strings.Join(fields[:len(fields)-1], " "), last
	}
	return v, ""
}

// techFromHeaders applies the rules to a response, through `get`, which
// returns a header's value or "" — so a net/http header and an httpx JSON
// row can both be read. Hints are unique by name; the first rule to name a
// technology wins, and a later versioned hint upgrades a versionless one.
func techFromHeaders(get func(header string) string) []techHint {
	var out []techHint
	index := map[string]int{}
	for _, rule := range headerTechRules {
		v := get(rule.Header)
		if v == "" {
			continue
		}
		for _, h := range rule.Hints(v) {
			key := strings.ToLower(h.Name)
			if i, seen := index[key]; seen {
				if out[i].Version == "" && h.Version != "" {
					out[i].Version = h.Version
				}
				continue
			}
			index[key] = len(out)
			out = append(out, h)
		}
	}
	return out
}

// techObservations turns hints into observations for a service, leaving out
// any technology `already` named (by a fuller fingerprint in the same batch).
func techObservations(ip string, port int, host string, hints []techHint, already map[string]bool) []scanproto.Observation {
	var obs []scanproto.Observation
	for _, h := range hints {
		if already[strings.ToLower(h.Name)] {
			continue
		}
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsTech, IP: ip, Port: port, Host: host,
			TechName: h.Name, TechVersion: h.Version, TechConfidence: h.Confidence,
		})
	}
	return obs
}

// httpxHeader reads a header from an httpx JSON row, whose "header" object
// keys are lower-case with underscores ("x_redirect_by").
func httpxHeader(row map[string]any) func(string) string {
	return func(name string) string {
		return headerField(row, strings.ReplaceAll(strings.ToLower(name), "-", "_"))
	}
}
