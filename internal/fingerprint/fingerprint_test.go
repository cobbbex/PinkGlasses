package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func top(t *testing.T, r Response) Match {
	t.Helper()
	ms := Settled(Detect(r))
	if len(ms) == 0 {
		t.Fatalf("nothing named; detect gave %+v", Detect(r))
	}
	return ms[0]
}

func TestRules(t *testing.T) {
	cases := []struct {
		name     string
		r        Response
		product  string
		version  string
		release  string
		features []string
	}{
		{"exchange by header", Response{Status: 302, Headers: http.Header{
			"X-Owa-Version": {"15.1.2507.39"}, "X-Feserver": {"EX01"}, "Location": {"/owa/auth/logon.aspx"}}},
			Exchange, "15.1.2507.39", "Exchange 2016", []string{"OWA"}},
		{"exchange by logon page build", Response{Status: 200, Title: "Outlook",
			Body: `<link rel="stylesheet" href="/owa/auth/15.2.1544/themes/resources/logon.css">`},
			Exchange, "15.2.1544", "Exchange 2019", []string{"OWA"}},
		{"exchange SE", Response{Status: 200, Body: `<script src="/owa/auth/15.2.2562/scripts/premium/flogon.js">`},
			Exchange, "15.2.2562", "Exchange Server SE", []string{"OWA"}},
		{"netscaler gateway with SAML", Response{Status: 302, Cookies: []string{"NSC_TASS"},
			Headers: http.Header{"Location": {"https://idp.example.org/sso?SAMLRequest=fZJb&RelayState=x"}}},
			NetScaler, "", "", []string{"Gateway", "SAML"}},
		{"netscaler logonpoint", Response{Status: 200, Title: "NetScaler Gateway",
			Body: `<script src="/logon/LogonPoint/receiver/js/ctxs.core.min.js"></script>`},
			NetScaler, "", "", []string{"Gateway"}},
		{"netscaler load balancer only", Response{Status: 200, Cookies: []string{"NSC_ESNS"}},
			NetScaler, "", "", nil},
		{"confluence", Response{Status: 200, Headers: http.Header{"X-Confluence-Request-Time": {"1712"}},
			Body: `<meta name="ajs-version-number" content="7.19.16"><meta name="ajs-confluence-flavour" content="VANILLA">`},
			Confluence, "7.19.16", "", nil},
		{"confluence applinks manifest", Response{Path: "/rest/applinks/1.0/manifest", Status: 200,
			Body: `<manifest><typeId>confluence</typeId><version>8.5.4</version></manifest>`},
			Confluence, "8.5.4", "", nil},
		{"jira meta", Response{Status: 200, Cookies: []string{"atlassian.xsrf.token", "JSESSIONID"},
			Headers: http.Header{"X-Arequestid": {"1x2"}},
			Body: `<meta name="application-name" content="JIRA" data-name="jira" data-version="9.12.2">` +
				`<meta name="ajs-version-number" content="9.12.2">`},
			Jira, "9.12.2", "", nil},
		{"jira serverInfo", Response{Path: "/rest/api/2/serverInfo", Status: 200,
			Body: `{"baseUrl":"https://jira.example.org","version":"8.20.10","versionNumbers":[8,20,10],"deploymentType":"Server","buildNumber":820010,"serverTitle":"Jira"}`},
			Jira, "8.20.10", "", nil},
		{"zammad", Response{Status: 200, Cookies: []string{"_zammad_session_4e8c1b2a"}},
			Zammad, "", "", nil},
		{"zammad getting started", Response{Path: "/api/v1/getting_started", Status: 200,
			Body: `{"setup_done":true,"import_mode":false,"import_backend":null,"system_online_service":false}`},
			Zammad, "", "", nil},
		{"zimbra login", Response{Status: 200, Title: "Zimbra Web Client Sign In", Cookies: []string{"ZM_TEST"}},
			Zimbra, "", "", nil},
		{"zimbra settings js", Response{Path: "/js/zimbraMail/share/model/ZmSettings.js", Status: 200,
			Body: `this.registerSetting("CLIENT_VERSION",{type:ZmSetting.T_CONFIG,defaultValue:"8.8.15_GA_4508",isGlobal:true});`},
			Zimbra, "8.8.15_GA_4508", "", nil},
		{"kerio", Response{Status: 302, Headers: http.Header{"Server": {"Kerio Connect 10.0.2 patch 1"}, "Location": {"/webmail/"}}},
			Kerio, "10.0.2 patch 1", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.r.Headers == nil {
				c.r.Headers = http.Header{}
			}
			m := top(t, c.r)
			if m.Product != c.product || m.Version != c.version || m.Release != c.release {
				t.Fatalf("got %s %q (%s), want %s %q (%s); evidence %v",
					m.Product, m.Version, m.Release, c.product, c.version, c.release, m.Evidence)
			}
			if strings.Join(m.Features, ",") != strings.Join(c.features, ",") {
				t.Errorf("features %v, want %v", m.Features, c.features)
			}
		})
	}
}

// Ordinary sites must not be named: a page mentioning Outlook, a WordPress
// blog, a Roundcube webmail at /webmail/, a bare nginx.
func TestNoFalsePositives(t *testing.T) {
	for name, r := range map[string]Response{
		"nginx":     {Status: 200, Headers: http.Header{"Server": {"nginx"}}, Title: "Welcome to nginx!"},
		"blog":      {Status: 200, Title: "Ten Outlook tips", Body: `<a href="/owa-tips/">tips</a> <meta name="generator" content="WordPress 6.6">`},
		"roundcube": {Status: 302, Headers: http.Header{"Location": {"/webmail/"}}},
		"iis":       {Status: 200, Headers: http.Header{"Server": {"Microsoft-IIS/10.0"}, "X-Powered-By": {"ASP.NET"}}, Title: "IIS Windows Server"},
		"bitbucket": {Status: 200, Headers: http.Header{"X-Arequestid": {"@1X"}}},
	} {
		if ms := Settled(Detect(r)); len(ms) > 0 {
			t.Errorf("%s: named %+v", name, ms)
		}
	}
}

// A weak hint is enough to earn the product's probes, and never more than
// MaxProbes of them; a settled, versioned match earns none.
func TestProbes(t *testing.T) {
	r := Response{Status: 302, Headers: http.Header{"Location": {"/owa/"}}}
	got := Probes(SameSitePath("https://mail.example.org", r), Detect(r), map[string]bool{"/": true})
	if strings.Join(got, " ") != "/owa/ /owa/auth/logon.aspx" {
		t.Errorf("probes %v", got)
	}
	settled := Response{Headers: http.Header{"X-Owa-Version": {"15.2.1544.4"}}}
	if got := Probes("", Detect(settled), nil); len(got) != 0 {
		t.Errorf("a settled match asked for %v", got)
	}
	everything := Response{Status: 200, Title: "jira confluence zimbra zammad outlook netscaler kerio connect"}
	if got := Probes("/x", Detect(everything), nil); len(got) > MaxProbes {
		t.Errorf("%d probes, cap is %d", len(got), MaxProbes)
	}
}

func TestSameSitePath(t *testing.T) {
	base := "https://wiki.example.org"
	for loc, want := range map[string]string{
		"/login.action?os_destination=%2F":          "/login.action",
		"https://wiki.example.org/dashboard.action": "/dashboard.action",
		"https://idp.example.com/sso?SAMLRequest=x": "",
		"//evil.example.com/":                       "",
		"http://wiki.example.org/x":                 "", // scheme change is another site
	} {
		r := Response{Status: 302, Headers: http.Header{"Location": {loc}}}
		if got := SameSitePath(base, r); got != want {
			t.Errorf("%s: got %q, want %q", loc, got, want)
		}
	}
}

// The fetcher follows a site from its front page to the version, without
// following the redirect anywhere itself and without leaving the site.
func TestFetcherFollowsOneSite(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/secure/Dashboard.jspa", http.StatusFound)
		case "/secure/Dashboard.jspa":
			w.Header().Set("X-AREQUESTID", "1")
			w.Write([]byte(`<html><title>System Dashboard - Jira</title></html>`))
		case "/rest/api/2/serverInfo":
			w.Write([]byte(`{"version":"9.4.17","versionNumbers":[9,4,17],"deploymentType":"Server","serverTitle":"Jira"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	res, err := Fetcher{Client: client}.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Product != Jira || res.Matches[0].Version != "9.4.17" {
		t.Fatalf("matches %+v", res.Matches)
	}
	if len(asked) > 1+MaxProbes {
		t.Errorf("asked %d paths: %v", len(asked), asked)
	}
}

// Every file in testdata/ is a response and the products it must be named
// as. Real banners land here through `fpcheck -fixtures`; each one is a case
// a rule change must not lose.
func TestFixtures(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.json")
	if len(files) == 0 {
		t.Skip("no fixtures")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var fx struct {
				Expect   []string `json:"expect"`
				Response Response `json:"response"`
			}
			if err := json.Unmarshal(data, &fx); err != nil {
				t.Fatal(err)
			}
			if fx.Response.Headers == nil {
				fx.Response.Headers = http.Header{}
			}
			named := map[string]bool{}
			for _, m := range Settled(Detect(fx.Response)) {
				named[m.Product] = true
			}
			for _, want := range fx.Expect {
				if !named[want] {
					t.Errorf("not named %s; detect gave %+v", want, Detect(fx.Response))
				}
			}
		})
	}
}
