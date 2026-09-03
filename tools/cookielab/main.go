// Command cookielab serves one page that sets the cookies real appliances set,
// so the cookie fingerprinting and `cookie:` search can be exercised end to end
// without pointing the scanner at somebody else's Cisco.
//
// The names are the interesting part: a product often sets a cookie whose name
// is unique to it, which identifies the box behind a port that gives nothing
// away in its banner or title. The values here are obvious fakes — the scanner
// records names only, and this makes that easy to confirm.
//
// Run it with the `lab` compose profile:
//
//	docker compose --profile lab up -d cookielab
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// cookie is one Set-Cookie the lab serves, with the product it imitates.
type cookie struct {
	name, value, product string
}

var cookies = []cookie{
	// Cisco ASA WebVPN — the case that prompted all this.
	{"webvpn", "fake-not-a-session", "Cisco ASA WebVPN"},
	{"webvpnlogin", "1", "Cisco ASA WebVPN"},
	{"webvpnLang", "en", "Cisco ASA WebVPN"},
	{"webvpn_portal", "fake-portal", "Cisco ASA WebVPN"},
	// F5 BIG-IP encodes the pool in the name, so the name alone is a finding.
	{"BIGipServerpool_web_https", "1234567890.20480.0000", "F5 BIG-IP"},
	// Citrix NetScaler / Gateway.
	{"NSC_wt_mfi", "fake-citrix", "Citrix NetScaler"},
	// Ordinary application cookies, so the lab is not all appliances.
	{"JSESSIONID", "fake-java-session", "Java application server"},
	{"PHPSESSID", "fake-php-session", "PHP application"},
}

func main() {
	addr := ":" + env("PORT", "80")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two paths exist; everything else is 404, and it has to be exactly 404.
		//
		// This deliberately does not use http.ServeMux. A mux matching "/"
		// answers 200 to every path, which made this target report a critical
		// "Cisco ASA directory traversal" for a Go program with no files — and
		// a mux also *cleans* paths, answering 301 to entries like
		// "render/https://www.google.com" that SecLists includes to probe for
		// SSRF. Either way a brute force reports hits that are not there, which
		// makes the target useless for telling a real finding from noise.
		switch r.URL.Path {
		case "/plain":
			// LAB_HIDE_PLAIN=1 makes this path vanish, so a finding can be made
			// to disappear between two scans and come back on a third — which
			// is the only way to test that history records a gap honestly.
			if os.Getenv("LAB_HIDE_PLAIN") == "1" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<!doctype html><title>No cookies here</title><h1>No cookies here</h1>")
			return
		case "/":
		default:
			http.NotFound(w, r)
			return
		}
		for _, c := range cookies {
			http.SetCookie(w, &http.Cookie{
				Name: c.name, Value: c.value, Path: "/",
			})
		}
		// A second Set-Cookie for a name already sent, because a real response
		// often repeats one and the scanner must record the name once.
		http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: "fake-duplicate", Path: "/"})

		w.Header().Set("Server", "CookieLab/1.0 (PinkGlasses test target)")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page())
	})

	log.Printf("cookielab listening on %s, serving %d cookies", addr, len(cookies)+1)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func page() string {
	rows := ""
	for _, c := range cookies {
		rows += fmt.Sprintf(
			"<tr><td><code>%s</code></td><td>%s</td><td><code>cookie:%s</code></td></tr>",
			c.name, c.product, c.name)
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Cookie Lab — PinkGlasses test target</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;margin:40px auto;max-width:760px;padding:0 16px;
      background:#14121a;color:#e8e6ef}
 h1{font-size:22px;margin-bottom:4px} .sub{color:#9a95ab;margin-top:0}
 table{border-collapse:collapse;width:100%;margin-top:18px}
 th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2b2735}
 th{color:#9a95ab;font-weight:600;font-size:13px}
 code{background:#221f2b;padding:1px 6px;border-radius:4px;color:#f2a5c4}
 p.note{color:#9a95ab;font-size:13px;margin-top:22px}
</style></head><body>
<h1>Cookie Lab</h1>
<p class="sub">A test target for PinkGlasses. This page sets the cookies below;
scan it, then search for any of them.</p>
<table>
  <thead><tr><th>Cookie name</th><th>Imitates</th><th>Find it with</th></tr></thead>
  <tbody>` + rows + `</tbody>
</table>
<p class="note">Values are obvious fakes. PinkGlasses records cookie
<strong>names</strong> only — a value is a session token and is never stored.
<code>/plain</code> serves no cookies, so you can check that a service without
them reports none.</p>
</body></html>`
}
