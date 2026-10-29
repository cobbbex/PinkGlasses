package fingerprint

import (
	"regexp"
	"strconv"
	"strings"
)

// The rules. Weights are how sure one signal makes us on its own: 90 and up
// for something only that product emits, 70–85 for a strong marker another
// product could plausibly share, 40–60 for a hint that only earns a probe.
// Every rule here should be checked against real banners with tools/fpcheck
// before its weight is trusted; testdata/ holds the cases that settled one.
var rules = []product{
	netscalerRule,
	confluenceRule,
	jiraRule,
	zammadRule,
	zimbraRule,
	exchangeRule,
	kerioRule,
}

// --- Citrix NetScaler (ADC / Gateway / AAA) ---
//
// NSC_* cookies are set by the appliance itself: on a load-balancing vserver
// for persistence, and NSC_TMAS/NSC_TEMP/NSC_AAAC on the Gateway and AAA
// logon flow. The logon pages live under /vpn/ (classic) and
// /logon/LogonPoint/ (RfWebUI). A NetScaler acting as a SAML service
// provider answers / with a redirect to the IdP carrying a SAMLRequest; one
// receiving the assertion does so at /cgi/samlauth.

var nsGatewayCookies = []string{"NSC_TMAS", "NSC_TEMP", "NSC_TMAA", "NSC_AAAC", "NSC_TASS", "NSC_DLGE", "NSC_EPAC"}

var nsBuildHash = regexp.MustCompile(`(?i)/vpn/js/[a-z_]+\.js\?v=([0-9a-f]{32})`)

var netscalerRule = product{
	name:    NetScaler,
	aliases: []string{"netscaler", "citrix", "citrix-adc", "citrix-gateway", "adc"},
	signals: []signal{
		{"cookie NSC_* (gateway/AAA)", 92, "Gateway", cookie(nsGatewayCookies...)},
		{"cookie NSC_*", 80, "", cookiePrefix("NSC_")},
		{"cookie citrix_ns_id", 85, "", cookie("citrix_ns_id")},
		{"redirect to /vpn/index.html", 88, "Gateway", locationHas("/vpn/index.html")},
		{"redirect to /logon/LogonPoint/", 92, "Gateway", locationHas("/logon/LogonPoint/")},
		{"redirect to nFactor /nf/auth/", 85, "AAA", locationHas("/nf/auth/")},
		{"body /vpn/ resources", 90, "Gateway", bodyHas("/vpn/resources/", "/vpn/js/", "/vpn/images/")},
		{"body LogonPoint", 92, "Gateway", bodyHas("/logon/LogonPoint/", "logonpoint/receiver")},
		{"body ctxs.* UI", 85, "Gateway", bodyHas("ctxs.authentication", "ctxs.core.min.js", "/logon/themes/")},
		{"title NetScaler AAA", 92, "AAA", titleHas("netscaler aaa")},
		{"title Gateway", 88, "Gateway", titleHas("netscaler gateway", "citrix gateway", "citrix access gateway")},
		{"title NetScaler", 80, "", titleHas("netscaler")},
		{"SAML ACS /cgi/samlauth", 70, "SAML", locationHas("/cgi/samlauth")},
		{"NetScaler SAML IdP /saml/login", 50, "SAML", func(r *Response) bool {
			return strings.HasPrefix(r.path(), "/saml/login") && r.Status == 200 && strings.Contains(strings.ToLower(r.Body), "saml")
		}},
	},
	probes: []string{"/vpn/index.html", "/logon/LogonPoint/tmindex.html"},
	extra: func(r *Response, m *Match) {
		// The ?v= hash on the Gateway's JavaScript changes with every build.
		// It is not a version until a table maps it to one, so it is kept as
		// evidence: two gateways with the same hash run the same build.
		if h := firstGroup(r.Body, nsBuildHash); h != "" {
			m.Evidence = append(m.Evidence, "build hash "+strings.ToLower(h))
		}
		// SAML in front of the gateway: the appliance answers with a redirect
		// to the IdP carrying an AuthnRequest, or a self-posting form with one.
		loc := r.Headers.Get("Location")
		if strings.Contains(loc, "SAMLRequest=") ||
			(strings.Contains(r.Body, `name="SAMLRequest"`) && strings.Contains(strings.ToLower(r.Body), "<form")) {
			m.Features = union(m.Features, []string{"SAML"})
			m.Evidence = append(m.Evidence, "SAML AuthnRequest")
		}
	},
}

// --- Atlassian Confluence ---

var (
	ajsVersion        = regexp.MustCompile(`(?i)<meta\s+name="ajs-version-number"\s+content="([0-9][0-9.]*)"`)
	confluenceFooter  = regexp.MustCompile(`(?i)id="footer-build-information"[^>]*>\s*([0-9][0-9.]*)`)
	confluencePowered = regexp.MustCompile(`(?i)Atlassian Confluence\s*(?:</a>\s*)?([0-9]+\.[0-9][0-9.]*)`)
	applinksVersion   = regexp.MustCompile(`(?is)<version>\s*([0-9][0-9.]*)\s*</version>`)
)

var confluenceRule = product{
	name:    Confluence,
	aliases: []string{"confluence"},
	signals: []signal{
		{"header X-Confluence-Request-Time", 95, "", hasHeader("X-Confluence-Request-Time")},
		{"header X-Confluence-Cluster-Node", 95, "", hasHeader("X-Confluence-Cluster-Node")},
		{"body confluence markup", 90, "", bodyHas("com-atlassian-confluence", "confluence-base-url", "ajs-confluence-flavour")},
		{"body Powered by Atlassian Confluence", 88, "", bodyHas("powered by atlassian confluence", "atlassian confluence</a>")},
		{"applinks manifest typeId confluence", 95, "", bodyHas("<typeid>confluence</typeid>")},
		{"title Confluence", 60, "", titleHas("confluence")},
		{"redirect to *.action", 45, "", func(r *Response) bool {
			l := strings.ToLower(r.Headers.Get("Location"))
			return strings.Contains(l, "/login.action") || strings.Contains(l, "/dashboard.action") || strings.Contains(l, "/homepage.action")
		}},
	},
	version: func(r *Response) string {
		if v := firstGroup(r.Body, confluenceFooter, confluencePowered); v != "" {
			return v
		}
		b := strings.ToLower(r.Body)
		if strings.Contains(b, "<typeid>confluence</typeid>") {
			return firstGroup(r.Body, applinksVersion)
		}
		// ajs-version-number is shared by every Atlassian server product.
		if strings.Contains(b, "confluence") && !strings.Contains(b, `data-name="jira"`) {
			return firstGroup(r.Body, ajsVersion)
		}
		return ""
	},
	probes: []string{"/login.action", "/rest/applinks/1.0/manifest"},
}

// --- Atlassian Jira ---
//
// X-AREQUESTID and friends come from Atlassian's Seraph/request filter, which
// Jira and Bitbucket share; on their own they say "Atlassian", not "Jira".

var (
	jiraAppVersion = regexp.MustCompile(`(?i)data-name="jira"\s+data-version="([0-9][0-9.]*)"`)
	jiraServerInfo = regexp.MustCompile(`"version"\s*:\s*"([0-9][0-9.]*)"`)
)

var jiraRule = product{
	name:    Jira,
	aliases: []string{"jira"},
	signals: []signal{
		{"meta application-name JIRA", 95, "", bodyHas(`name="application-name" content="jira"`, `data-name="jira"`)},
		{"serverInfo JSON", 95, "", bodyHasAll(`"deploymenttype"`, `"versionnumbers"`, `"servertitle"`)},
		{"applinks manifest typeId jira", 95, "", bodyHas("<typeid>jira</typeid>")},
		{"body jira web resources", 85, "", bodyHas("jira.webresources", "/secure/projectavatar", "jira-help-tip")},
		{"redirect to Jira page", 80, "", func(r *Response) bool {
			l := strings.ToLower(r.Headers.Get("Location"))
			return strings.Contains(l, "/secure/dashboard.jspa") || strings.Contains(l, "/login.jsp") || strings.Contains(l, "/secure/myjirahome.jspa")
		}},
		{"cookie atlassian.xsrf.token", 70, "", cookie("atlassian.xsrf.token")},
		{"header X-ASEN/X-AUSERNAME", 60, "", func(r *Response) bool {
			return r.Headers.Get("X-ASEN") != "" || r.Headers.Get("X-AUSERNAME") != "" || r.Headers.Get("X-ASESSIONID") != ""
		}},
		{"header X-AREQUESTID", 50, "", hasHeader("X-AREQUESTID")},
		{"title Jira", 65, "", titleHas("jira")},
	},
	version: func(r *Response) string {
		if v := firstGroup(r.Body, jiraAppVersion); v != "" {
			return v
		}
		b := strings.ToLower(r.Body)
		if strings.Contains(b, `"deploymenttype"`) {
			return firstGroup(r.Body, jiraServerInfo)
		}
		if strings.Contains(b, "<typeid>jira</typeid>") {
			return firstGroup(r.Body, applinksVersion)
		}
		return ""
	},
	probes: []string{"/rest/api/2/serverInfo", "/login.jsp"},
}

// --- Zammad ---
//
// The front page is a single-page app that names itself only in its assets,
// so the session cookie and /api/v1/getting_started (public: the setup
// wizard reads it before anyone signs in) carry the weight.

var zammadRule = product{
	name:    Zammad,
	aliases: []string{"zammad"},
	signals: []signal{
		{"cookie _zammad_session_*", 95, "", cookiePrefix("_zammad_session")},
		{"getting_started JSON", 92, "", bodyHasAll(`"setup_done"`, `"import_mode"`)},
		{"title Zammad", 85, "", titleHas("zammad")},
		{"body zammad", 70, "", bodyHas("zammad")},
	},
	probes: []string{"/api/v1/getting_started"},
}

// --- Zimbra ---

var zimbraClientVersion = regexp.MustCompile(`CLIENT_VERSION"\s*,\s*\{[^}]*?defaultValue\s*:\s*"([0-9][^"@]*)"`)

var zimbraRule = product{
	name:    Zimbra,
	aliases: []string{"zimbra"},
	signals: []signal{
		{"cookie ZM_*", 92, "", cookie("ZM_TEST", "ZM_LOGIN_CSRF", "ZM_AUTH_TOKEN", "ZM_ADMIN_AUTH_TOKEN")},
		{"title Zimbra Web Client", 95, "", titleHas("zimbra web client")},
		{"body zimbraMail", 90, "", bodyHas("/js/zimbramail/", "zimbramail", "zimbra web client")},
		{"ZmSettings.js", 95, "", bodyHas("zmsetting.t_config")},
		{"title Zimbra", 80, "", titleHas("zimbra")},
		{"body Zimbra", 65, "", bodyHas("zimbra")},
	},
	version: func(r *Response) string { return firstGroup(r.Body, zimbraClientVersion) },
	probes:  []string{"/js/zimbraMail/share/model/ZmSettings.js"},
}

// --- Microsoft Exchange (OWA / ECP) ---
//
// OWA's logon page loads its themes and scripts from /owa/auth/<build>/, so
// the page itself carries the build; X-OWA-Version carries it outright.

var owaBuild = regexp.MustCompile(`(?i)/owa/(?:auth/)?([0-9]{1,2}\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)/`)

var exchangeRule = product{
	name:    Exchange,
	aliases: []string{"exchange", "owa", "msexchange"},
	signals: []signal{
		{"header X-OWA-Version", 97, "OWA", hasHeader("X-OWA-Version")},
		{"header X-FEServer/X-BEServer", 90, "", func(r *Response) bool {
			return r.Headers.Get("X-FEServer") != "" || r.Headers.Get("X-BEServer") != "" || r.Headers.Get("X-CalculatedBETarget") != ""
		}},
		{"body /owa/auth/<build>/", 95, "OWA", bodyMatches(owaBuild)},
		{"body OWA logon form", 85, "OWA", bodyHas("/owa/auth.owa", "owa/auth/logon.aspx", "flogon.js")},
		{"redirect to /owa/", 70, "OWA", locationHas("/owa/")},
		{"redirect to /ecp/", 65, "ECP", locationHas("/ecp/")},
		{"title Outlook", 55, "OWA", titleHas("outlook web app", "outlook web access", "outlook")},
		{"header X-DiagInfo", 50, "", hasHeader("X-DiagInfo")},
	},
	version: func(r *Response) string {
		if v := strings.TrimSpace(r.Headers.Get("X-OWA-Version")); v != "" {
			return v
		}
		return firstGroup(r.Body, owaBuild)
	},
	probes: []string{"/owa/auth/logon.aspx"},
	extra: func(r *Response, m *Match) {
		m.Release = exchangeRelease(m.Version)
	},
}

// exchangeRelease names the Exchange release a build belongs to. Every 15.x
// release shares the major number, so the minor (and for SE the build) decide.
func exchangeRelease(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return ""
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ""
	}
	switch {
	case major == 8:
		return "Exchange 2007"
	case major == 14:
		return "Exchange 2010"
	case major == 15 && minor == 0:
		return "Exchange 2013"
	case major == 15 && minor == 1:
		return "Exchange 2016"
	case major == 15 && minor == 2:
		// Subscription Edition RTM is 15.2.2562.17; 2019 CU15 is 15.2.1748.
		if len(parts) > 2 {
			if b, err := strconv.Atoi(parts[2]); err == nil && b >= 2562 {
				return "Exchange Server SE"
			}
		}
		return "Exchange 2019"
	}
	return ""
}

// --- Kerio Connect ---

var kerioServer = regexp.MustCompile(`(?i)Kerio (?:Connect|MailServer)\s+([0-9][0-9A-Za-z. ]*)`)

var kerioRule = product{
	name:    Kerio,
	aliases: []string{"kerio", "kerio-connect"},
	signals: []signal{
		{"Server Kerio Connect", 97, "", headerHas("Server", "kerio connect")},
		{"Server Kerio MailServer", 92, "", headerHas("Server", "kerio mailserver")},
		{"title Kerio Connect", 92, "", titleHas("kerio connect")},
		{"cookie *_CONNECT_WEBMAIL", 85, "", cookie("SESSION_CONNECT_WEBMAIL", "TOKEN_CONNECT_WEBMAIL")},
		{"body Kerio Connect", 85, "", bodyHas("kerio connect", "kerio technologies")},
		{"redirect to /webmail/", 45, "", locationHas("/webmail/")},
	},
	version: func(r *Response) string {
		return strings.TrimSpace(firstGroup(r.Headers.Get("Server"), kerioServer))
	},
	probes: []string{"/webmail/login/"},
}
