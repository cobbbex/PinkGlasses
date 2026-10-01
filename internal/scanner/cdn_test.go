package scanner

import "testing"

// Six of the eight addresses a real company's three domains resolved to
// belonged to Cloudflare or Akamai, and a full-port sweep spent eighteen hours
// of probing on them. These are the exact operator names the registries
// returned for those addresses.
func TestCDNProviderRecognisesWhatTheRegistriesSay(t *testing.T) {
	cdn := []struct {
		asn   int
		org   string
		where string
	}{
		{13335, "CLOUDFLARENET - Cloudflare, Inc., US", "cloudflare"},
		{33905, "AKAMAI-AMS - Akamai International B.V., NL", "akamai"},
		{54113, "FASTLY - Fastly, Inc.", "fastly"},
		{0, "INCAPSULA - Incapsula Inc", "imperva"}, // name only, no ASN match
		{0, "AMAZON-02 - Amazon.com (CloudFront)", "cloudfront"},
		{999999, "G-Core Labs S.A.", "gcore"}, // unknown ASN, known name
	}
	for _, c := range cdn {
		if got := cdnProvider(c.asn, c.org); got != c.where {
			t.Errorf("cdnProvider(%d, %q) = %q, want %q", c.asn, c.org, got, c.where)
		}
	}

	// A host in a cloud is usually the client's own machine. Refusing to scan
	// those would refuse most of the modern internet, so they must not match.
	for _, c := range []struct {
		asn int
		org string
	}{
		{39608, "LANETUA-AS - Lanet Network Ltd, UA"},
		{16509, "AMAZON-02 - Amazon.com, Inc."},
		{15169, "GOOGLE - Google LLC"},
		{8075, "MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation"},
		{24940, "HETZNER-AS - Hetzner Online GmbH"},
		{14061, "DIGITALOCEAN-ASN - DigitalOcean, LLC"},
		{0, ""},
	} {
		if got := cdnProvider(c.asn, c.org); got != "" {
			t.Errorf("cdnProvider(%d, %q) = %q; an ordinary host must be scannable", c.asn, c.org, got)
		}
	}
}
