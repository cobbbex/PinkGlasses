package scanner

import (
	htmlstd "html"
	"regexp"
	"strings"

	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// A PHP error printed into a page proves the site runs PHP, and it gives away
// where the code lives on disk — "/var/www/html/app/index.php", the account
// name in "/home/acme/public_html", a framework's directory layout. That is
// display_errors left on in production, and worth a finding of its own.
//
// PHP prints them two ways. The classic form, as HTML:
//
//	<b>Warning</b>:  include(x.php): Failed to open stream in <b>/var/www/html/index.php</b> on line <b>12</b>
//
// and an uncaught exception, from PHP 7 on:
//
//	PHP Fatal error:  Uncaught Error: Call to undefined function foo() in /var/www/html/x.php:12

var (
	phpTagRe = regexp.MustCompile(`<[^>]{0,200}>`)
	// The path must look like one: absolute (Unix or a drive letter) and
	// ending in a PHP source extension, so prose that happens to say
	// "Warning: … in … on line" does not match.
	phpErrorClassic = regexp.MustCompile(`(?i)\b(Fatal error|Parse error|Warning|Notice|Deprecated|Recoverable fatal error)\s*:\s+` +
		`(.{1,300}?)\s+in\s+((?:/|[A-Za-z]:\\)[^\s<>"']{1,250}?\.(?:php\d?|inc|phtml))\s+on\s+line\s+(\d{1,7})`)
	phpErrorUncaught = regexp.MustCompile(`(?i)\b(Fatal error)\s*:\s+(Uncaught .{1,300}?)\s+in\s+` +
		`((?:/|[A-Za-z]:\\)[^\s<>"']{1,250}?\.(?:php\d?|inc|phtml)):(\d{1,7})`)
)

type phpError struct {
	Level, Message, Path, Line string
}

// phpErrors finds the PHP error messages in a page body, at most a few:
// one is the finding, the rest only make the evidence longer.
func phpErrors(body string) []phpError {
	if body == "" {
		return nil
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, " on line") && !strings.Contains(lower, "uncaught") {
		return nil // the cheap test first: most pages have neither
	}
	text := htmlstd.UnescapeString(phpTagRe.ReplaceAllString(body, ""))
	var out []phpError
	seen := map[string]bool{}
	for _, re := range []*regexp.Regexp{phpErrorUncaught, phpErrorClassic} {
		for _, m := range re.FindAllStringSubmatch(text, 3) {
			key := m[3] + ":" + m[4]
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, phpError{
				Level:   m[1],
				Message: strings.Join(strings.Fields(m[2]), " "),
				Path:    m[3],
				Line:    m[4],
			})
		}
	}
	return out
}

// phpErrorObservations turns the errors on one page into a finding and a PHP
// technology. The finding's evidence names the URL and the first error; the
// message is clipped, since it is the site's text, not ours.
func phpErrorObservations(ip string, port int, host, url string, errs []phpError) []scanproto.Observation {
	if len(errs) == 0 {
		return nil
	}
	e := errs[0]
	msg := e.Message
	if len(msg) > 160 {
		msg = msg[:159] + "…"
	}
	evidence := url + " — " + e.Level + ": " + msg + " in " + e.Path + " on line " + e.Line
	if len(errs) > 1 {
		evidence += " (+" + itoaSafe(len(errs)-1) + " more)"
	}
	return []scanproto.Observation{
		{
			Type: scanproto.ObsFinding, IP: ip, Port: port, Host: host,
			FindingKind:     "php_error_disclosure",
			FindingSeverity: "low",
			FindingTitle:    "PHP error message discloses a server path",
			Banner:          evidence,
		},
		{
			Type: scanproto.ObsTech, IP: ip, Port: port, Host: host,
			TechName: "PHP", TechConfidence: 90,
		},
	}
}
