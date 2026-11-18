package fingerprint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Java application servers and frameworks, and the Java runtime under them.
//
// Most of them say what they are on an error page rather than on the front
// page, which is the application's own: Tomcat prints its version under a
// 404, Jetty signs its error page, WebLogic answers with RFC 2068's text,
// Spring Boot with its Whitelabel page or its JSON error. So every rule here
// shares one probe, javaNotFound, a page that does not exist, asked for once
// whichever of them made the site suspected — a JSESSIONID cookie is enough.
//
// The Java version itself is stated only by a few: GlassFish and Payara in
// X-Powered-By ("… Java/Oracle Corporation/1.8"), Spring Boot's
// /actuator/info when its Java contributor is on. Everywhere else the
// version is the oldest Java the named server runs on (InferJava), written
// "11+" so it cannot be read as the release itself.

const (
	Java      = "Java"
	Tomcat    = "Apache Tomcat"
	Jetty     = "Jetty"
	WildFly   = "WildFly"
	JBoss     = "JBoss Application Server"
	WebLogic  = "Oracle WebLogic Server"
	GlassFish = "GlassFish"
	Payara    = "Payara"
	WebSphere = "IBM WebSphere"
	Spring    = "Spring Boot"
)

// javaNotFound is a page no application has. A .jsp, so a container hands it
// to its JSP engine and answers with its own error page even where static
// files are served by something else in the same container.
const javaNotFound = "/nonexistent-page.jsp"

// --- Java (the runtime) ---

var (
	javaPoweredBy  = regexp.MustCompile(`(?i)\bJava/([^/)]+)/([0-9][0-9._]*)`)
	actuatorJava   = regexp.MustCompile(`(?s)"java"\s*:\s*\{[^{}]*?"version"\s*:\s*"([0-9][^"]*)"`)
	servletSpec    = regexp.MustCompile(`(?i)\bServlet[/ ]([0-9]+\.[0-9]+)`)
	javaPageLinks  = regexp.MustCompile(`(?i)(?:href|action|src)\s*=\s*["'][^"']*\.(?:jsp|jspx|do|jsf|faces|xhtml\?jsessionid)(?:[?"'#;])`)
	jsessionInBody = regexp.MustCompile(`(?i);jsessionid=[0-9a-z._-]{8,}`)
)

var javaRule = product{
	name:    Java,
	aliases: []string{"java", "jvm", "jre", "jdk"},
	signals: []signal{
		{"X-Powered-By Java/<vendor>/<version>", 97, "", func(r *Response) bool {
			return javaPoweredBy.MatchString(r.Headers.Get("X-Powered-By"))
		}},
		{"actuator info java.version", 97, "", func(r *Response) bool {
			return strings.HasPrefix(r.path(), "/actuator/info") && actuatorJava.MatchString(r.Body)
		}},
		{"X-Powered-By Servlet/JSP", 85, "", func(r *Response) bool {
			v := strings.ToLower(r.Headers.Get("X-Powered-By"))
			return strings.Contains(v, "servlet") || strings.Contains(v, "jsp/")
		}},
		{"URL ;jsessionid=", 85, "", bodyMatches(jsessionInBody)},
		{"body JSF ViewState", 85, "", bodyHas("javax.faces.viewstate", "jakarta.faces.viewstate")},
		{"cookie JSESSIONID", 75, "", cookie("JSESSIONID")},
		{"links to .jsp/.do/.jsf pages", 55, "", bodyMatches(javaPageLinks)},
	},
	version: func(r *Response) string {
		if m := javaPoweredBy.FindStringSubmatch(r.Headers.Get("X-Powered-By")); m != nil {
			return javaVersion(m[2])
		}
		if strings.HasPrefix(r.path(), "/actuator/info") {
			if v := firstGroup(r.Body, actuatorJava); v != "" {
				return javaVersion(v)
			}
		}
		// The servlet spec a container implements sets the oldest Java it
		// can run on.
		if spec := firstGroup(r.Headers.Get("X-Powered-By"), servletSpec); spec != "" {
			if n := servletFloor(spec); n > 0 {
				return floorVersion(n)
			}
		}
		return ""
	},
	probes: []string{javaNotFound},
	extra: func(r *Response, m *Match) {
		if p := javaPoweredBy.FindStringSubmatch(r.Headers.Get("X-Powered-By")); p != nil {
			m.Evidence = append(m.Evidence, "vendor "+strings.TrimSpace(p[1]))
		}
		if spec := firstGroup(r.Headers.Get("X-Powered-By"), servletSpec); spec != "" {
			if n := servletFloor(spec); n > 0 {
				m.Evidence = append(m.Evidence, fmt.Sprintf("Servlet %s needs Java %d or later", spec, n))
			}
		}
	},
}

// javaVersion writes a Java version the way it is spoken of: 1.8.0_392 is
// Java 8 update 392, "8u392"; 1.7 is 7; 17.0.9+9 is 17.0.9.
func javaVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, "+ -"); i > 0 {
		v = v[:i]
	}
	if strings.HasPrefix(v, "1.") {
		rest := v[2:]
		major, update, _ := strings.Cut(rest, "_")
		major, _, _ = strings.Cut(major, ".")
		if update != "" {
			return major + "u" + update
		}
		return major
	}
	return v
}

// floorVersion is how a Java version known only as a minimum is written:
// "11+", 11 or later. A stated version never ends in "+" (javaVersion
// drops the build suffix), so the two cannot be confused.
func floorVersion(n int) string { return strconv.Itoa(n) + "+" }

// IsFloor reports whether a version is only a minimum ("11+").
func IsFloor(v string) bool { return strings.HasSuffix(v, "+") }

func floorOf(v string) int {
	n, _ := strconv.Atoi(strings.TrimSuffix(v, "+"))
	return n
}

// servletFloor is the oldest Java a Servlet spec's containers run on.
func servletFloor(spec string) int {
	switch spec {
	case "6.1":
		return 17
	case "6.0":
		return 11
	case "5.0", "4.0":
		return 8
	case "3.1":
		return 7
	case "3.0":
		return 6
	case "2.5":
		return 5
	}
	return 0
}

// --- Apache Tomcat ---
//
// The default page is titled "Apache Tomcat/9.0.83"; the error pages print
// the same in an <h3> unless showServerInfo is off, and keep their styling
// (#525D76) when it is. Up to 8.0 the connector named itself in Server
// (Apache-Coyote/1.1). The manager answers without a login with a 401 whose
// realm is "Tomcat Manager Application", or a 403 naming the manager-gui role.

var tomcatVersion = regexp.MustCompile(`Apache Tomcat/([0-9]+\.[0-9]+[0-9.]*(?:-M[0-9]+)?)`)

var tomcatRule = product{
	name:    Tomcat,
	aliases: []string{"tomcat", "apache-tomcat"},
	signals: []signal{
		{"title Apache Tomcat/<version>", 97, "", func(r *Response) bool { return tomcatVersion.MatchString(r.Title) }},
		{"body Apache Tomcat/<version>", 95, "", bodyMatches(tomcatVersion)},
		{"body Tomcat default page", 92, "", bodyHas("you've successfully installed tomcat")},
		{"realm Tomcat Manager Application", 97, "Manager", headerHas("WWW-Authenticate", "tomcat manager application")},
		{"body manager-gui role", 90, "Manager", bodyHasAll("manager-gui", "tomcat-users.xml")},
		{"Tomcat error page style", 80, "", func(r *Response) bool {
			return strings.HasPrefix(strings.ToLower(r.Title), "http status") &&
				strings.Contains(strings.ToLower(r.Body), "background-color:#525d76")
		}},
		{"Server Apache-Coyote", 80, "", headerHas("Server", "apache-coyote")},
	},
	version: func(r *Response) string { return firstGroup(r.Title+"\n"+r.Body, tomcatVersion) },
	probes:  []string{javaNotFound, "/manager/html"},
}

// --- Jetty ---

var (
	jettyServer  = regexp.MustCompile(`(?i)jetty\(([0-9][^)]*)\)`)
	jettyPowered = regexp.MustCompile(`(?i)Powered by Jetty://\s*([0-9][0-9A-Za-z._-]*)`)
)

var jettyRule = product{
	name:    Jetty,
	aliases: []string{"jetty", "eclipse-jetty"},
	signals: []signal{
		{"Server Jetty(<version>)", 97, "", func(r *Response) bool { return jettyServer.MatchString(r.Headers.Get("Server")) }},
		{"body Powered by Jetty://", 95, "", bodyHas("powered by jetty://")},
		{"body Jetty HTTP ERROR table", 85, "", bodyHasAll("<h2>http error", "<th>uri:</th>", "<th>status:</th>")},
		{"Server Jetty", 85, "", headerHas("Server", "jetty")},
	},
	version: func(r *Response) string {
		if v := firstGroup(r.Headers.Get("Server"), jettyServer); v != "" {
			return v
		}
		return firstGroup(r.Body, jettyPowered)
	},
	probes: []string{javaNotFound},
}

// --- WildFly ---

var wildflyVersion = regexp.MustCompile(`(?i)WildFly(?:/| Full | )([0-9]+(?:\.[0-9]+)*(?:\.Final)?)`)

var wildflyRule = product{
	name:    WildFly,
	aliases: []string{"wildfly"},
	signals: []signal{
		{"title Welcome to WildFly", 97, "", titleHas("welcome to wildfly")},
		{"Server WildFly", 95, "", headerHas("Server", "wildfly")},
		{"X-Powered-By WildFly", 95, "", headerHas("X-Powered-By", "wildfly")},
		{"realm ManagementRealm", 92, "Management", headerHas("WWW-Authenticate", `realm="managementrealm"`)},
		{"title HAL Management Console", 90, "Management", titleHas("hal management console")},
		{"X-Powered-By Undertow", 65, "", headerHas("X-Powered-By", "undertow")},
	},
	version: func(r *Response) string {
		return firstGroup(r.Headers.Get("Server")+"\n"+r.Headers.Get("X-Powered-By")+"\n"+r.Title, wildflyVersion)
	},
	probes: []string{javaNotFound},
}

// --- JBoss Application Server / JBoss EAP ---

var jbossPowered = regexp.MustCompile(`(?i)JBoss(?:AS|EAP)?-([0-9][0-9.]*)`)

var jbossRule = product{
	name:    JBoss,
	aliases: []string{"jboss", "jboss-as", "jboss-eap", "eap"},
	signals: []signal{
		{"X-Powered-By JBoss", 95, "", headerHas("X-Powered-By", "jboss")},
		{"title Welcome to JBoss", 95, "", titleHas("welcome to jboss", "jboss eap", "jboss enterprise application platform")},
		{"body JBoss Web/<version>", 92, "", bodyHas("<h3>jboss web/", "jbossweb/")},
		{"body JMX console link", 80, "JMX Console", bodyHas(`href="/jmx-console`)},
	},
	version: func(r *Response) string { return firstGroup(r.Headers.Get("X-Powered-By"), jbossPowered) },
	probes:  []string{javaNotFound},
	extra: func(r *Response, m *Match) {
		if strings.Contains(strings.ToLower(r.Title+" "+r.Headers.Get("X-Powered-By")), "eap") ||
			strings.Contains(strings.ToLower(r.Body), "enterprise application platform") {
			m.Release = "JBoss EAP"
		}
	},
}

// --- Oracle WebLogic Server ---

var weblogicVersion = regexp.MustCompile(`(?i)WebLogic Server(?: Version:)?\s*([0-9]+\.[0-9]+[0-9.]*)`)

var weblogicRule = product{
	name:    WebLogic,
	aliases: []string{"weblogic", "oracle-weblogic"},
	signals: []signal{
		{"title WebLogic Administration Console", 97, "Console", titleHas("oracle weblogic server administration console", "weblogic server administration console")},
		{"body WebLogic Server Version", 97, "Console", bodyHas("weblogic server version:")},
		{"cookie ADMINCONSOLESESSION", 95, "Console", cookie("ADMINCONSOLESESSION")},
		{"Server WebLogic", 95, "", headerHas("Server", "weblogic")},
		{"redirect to /console/login/LoginForm.jsp", 92, "Console", locationHas("/console/login/loginform.jsp")},
		{"body WebLogic 404 page", 92, "", bodyHasAll("error 404--not found", "from rfc 2068 hypertext transfer protocol")},
	},
	version: func(r *Response) string {
		return firstGroup(r.Headers.Get("Server")+"\n"+r.Body, weblogicVersion)
	},
	probes: []string{javaNotFound, "/console/login/LoginForm.jsp"},
}

// --- GlassFish ---

var glassfishVersion = regexp.MustCompile(`(?i)GlassFish(?: Server Open Source Edition| Server)?\s+([0-9]+\.[0-9]+[0-9.]*)`)

// notPayara: Payara is GlassFish's fork and still mentions it.
func notPayara(t func(*Response) bool) func(*Response) bool {
	return func(r *Response) bool {
		all := strings.ToLower(r.Headers.Get("Server") + r.Headers.Get("X-Powered-By") + r.Title)
		return t(r) && !strings.Contains(all, "payara")
	}
}

var glassfishRule = product{
	name:    GlassFish,
	aliases: []string{"glassfish", "eclipse-glassfish"},
	signals: []signal{
		{"Server GlassFish", 97, "", notPayara(headerHas("Server", "glassfish"))},
		{"X-Powered-By GlassFish", 95, "", notPayara(headerHas("X-Powered-By", "glassfish"))},
		{"title GlassFish", 92, "", notPayara(titleHas("glassfish"))},
	},
	version: func(r *Response) string {
		return firstGroup(r.Headers.Get("Server")+"\n"+r.Headers.Get("X-Powered-By")+"\n"+r.Title, glassfishVersion)
	},
	probes: []string{javaNotFound},
}

// --- Payara ---

var payaraVersion = regexp.MustCompile(`(?i)Payara (?:Server|Micro)\s+([0-9]+\.[0-9]+[0-9.]*)`)

var payaraRule = product{
	name:    Payara,
	aliases: []string{"payara", "payara-server", "payara-micro"},
	signals: []signal{
		{"Server Payara", 97, "", headerHas("Server", "payara")},
		{"X-Powered-By Payara", 95, "", headerHas("X-Powered-By", "payara")},
		{"title Payara", 92, "", titleHas("payara")},
		{"body #badassfish", 85, "", bodyHas("#badassfish")},
	},
	version: func(r *Response) string {
		return firstGroup(r.Headers.Get("Server")+"\n"+r.Headers.Get("X-Powered-By")+"\n"+r.Title+"\n"+r.Body, payaraVersion)
	},
	probes: []string{javaNotFound},
}

// --- IBM WebSphere (traditional and Liberty) ---

var websphereVersion = regexp.MustCompile(`(?i)WebSphere Application Server/([0-9][0-9.]*)`)

var websphereRule = product{
	name:    WebSphere,
	aliases: []string{"websphere", "liberty", "open-liberty", "was"},
	signals: []signal{
		{"Server WebSphere Application Server", 97, "", headerHas("Server", "websphere application server")},
		{"title WebSphere Integrated Solutions Console", 97, "Console", titleHas("websphere integrated solutions console")},
		{"body SRVE0190E (web container)", 95, "", bodyHas("srve0190e")},
		{"title Liberty", 90, "", titleHas("open liberty", "websphere liberty")},
		{"cookie WASReqURL", 92, "", cookie("WASReqURL")},
		{"redirect to /ibm/console", 90, "Console", locationHas("/ibm/console")},
		{"cookie LtpaToken2", 85, "", cookie("LtpaToken2")},
	},
	version: func(r *Response) string { return firstGroup(r.Headers.Get("Server"), websphereVersion) },
	probes:  []string{javaNotFound, "/ibm/console"},
	extra: func(r *Response, m *Match) {
		t := strings.ToLower(r.Title)
		switch {
		case strings.Contains(t, "open liberty"):
			m.Release = "Open Liberty"
		case strings.Contains(t, "websphere liberty"):
			m.Release = "WebSphere Liberty"
		}
	},
}

// --- Spring Boot ---
//
// The Whitelabel page and the JSON error both come from Boot's own error
// controller; actuator responses carry Boot's own media type. An actuator
// that lists env, heapdump and the like hands out what an attacker wants
// most, so each such endpoint is a feature of its own.

var (
	springJSONError = regexp.MustCompile(`(?s)^\s*\{\s*"timestamp"\s*:\s*[^,]+,\s*"status"\s*:\s*[0-9]{3}\s*,\s*"error"\s*:\s*"[^"]*"\s*,.*"path"\s*:\s*"`)
	actuatorLink    = regexp.MustCompile(`"([a-z][a-zA-Z0-9-]*)"\s*:\s*\{\s*"href"\s*:\s*"[^"]*/actuator/`)
)

// actuatorRisky are the endpoints that give away secrets or control.
var actuatorRisky = map[string]bool{
	"env": true, "heapdump": true, "threaddump": true, "jolokia": true, "shutdown": true,
	"gateway": true, "logfile": true, "configprops": true, "mappings": true, "httptrace": true,
	"httpexchanges": true, "loggers": true, "restart": true, "refresh": true, "trace": true,
}

func isActuatorIndex(r *Response) bool {
	return strings.Contains(r.Body, `"_links"`) && strings.Contains(r.Body, `/actuator"`)
}

var springRule = product{
	name:    Spring,
	aliases: []string{"spring", "spring-boot", "springboot", "actuator"},
	signals: []signal{
		{"body Whitelabel Error Page", 97, "", bodyHasAll("whitelabel error page", "no explicit mapping for /error")},
		{"Content-Type spring-boot.actuator", 97, "Actuator", headerHas("Content-Type", "spring-boot.actuator")},
		{"actuator index _links", 95, "Actuator", isActuatorIndex},
		{"Spring Boot JSON error", 80, "", bodyMatches(springJSONError)},
	},
	probes: []string{javaNotFound, "/actuator", "/actuator/info"},
	extra: func(r *Response, m *Match) {
		if !isActuatorIndex(r) {
			return
		}
		for _, g := range actuatorLink.FindAllStringSubmatch(r.Body, -1) {
			if actuatorRisky[g[1]] {
				m.Features = union(m.Features, []string{"Actuator " + g[1]})
			}
		}
	},
}

// --- the Java a named server needs ---

// javaFloor is the oldest Java a server release runs on, 0 when unknown.
func javaFloor(product, version string) int {
	major, minor := majorMinor(version)
	if major < 0 {
		return 0
	}
	at := func(maj, min int) bool { return major > maj || (major == maj && minor >= min) }
	switch product {
	case Tomcat:
		switch {
		case at(11, 0):
			return 17
		case at(10, 1):
			return 11
		case at(9, 0): // 9 and 10.0
			return 8
		case at(8, 0): // 8.0 and 8.5
			return 7
		case at(7, 0):
			return 6
		case at(6, 0):
			return 5
		}
	case Jetty:
		switch {
		case at(12, 0):
			return 17
		case at(10, 0):
			return 11
		case at(9, 3):
			return 8
		case at(9, 0):
			return 7
		case at(8, 0):
			return 6
		case at(7, 0):
			return 5
		}
	case WildFly:
		switch {
		case at(35, 0):
			return 17
		case at(27, 0):
			return 11
		case at(10, 0):
			return 8
		case at(8, 0):
			return 7
		}
	case GlassFish:
		switch {
		case at(8, 0):
			return 21
		case at(7, 0):
			return 11
		case at(6, 2):
			return 11
		case at(5, 0):
			return 8
		case at(4, 0):
			return 7
		case at(3, 0):
			return 6
		}
	case Payara:
		switch {
		case at(7, 0):
			return 21
		case at(6, 0):
			return 11
		case at(5, 0):
			return 8
		case at(4, 0):
			return 7
		}
	case WebLogic:
		switch {
		case at(14, 1) && !strings.HasPrefix(version, "14.1.1"): // 14.1.2, 15.1
			return 17
		case at(12, 2): // 12.2.1, 14.1.1
			return 8
		case strings.HasPrefix(version, "12.1.3"):
			return 7
		case at(10, 3):
			return 6
		}
	case WebSphere:
		switch {
		case at(9, 0):
			return 8
		case at(7, 0):
			return 6
		}
	}
	return 0
}

func majorMinor(v string) (int, int) {
	parts := strings.SplitN(v, ".", 3)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return -1, -1
	}
	minor := 0
	if len(parts) > 1 {
		digits := strings.TrimRightFunc(parts[1], func(c rune) bool { return c < '0' || c > '9' })
		minor, _ = strconv.Atoi(digits)
	}
	return major, minor
}

// InferJava adds what the named Java servers say about the Java under them:
// a server is itself evidence of Java, and its release sets the oldest Java
// it runs on. A version Java stated outright is kept; a minimum is raised to
// the highest any named server needs.
func InferJava(ms []Match) []Match {
	at := -1
	for i, m := range ms {
		if m.Product == Java {
			at = i
		}
	}
	floor, conf, why := 0, 0, ""
	for _, m := range ms {
		if m.Product == Java || m.Confidence < Reported {
			continue
		}
		if !isJavaServer(m.Product) {
			continue
		}
		conf = max(conf, m.Confidence)
		if n := javaFloor(m.Product, m.Version); n > floor {
			floor = n
			why = fmt.Sprintf("%s %s needs Java %d or later", m.Product, m.Version, n)
		}
	}
	if conf == 0 {
		return ms
	}
	if at < 0 {
		ms = append(ms, Match{Product: Java, Confidence: conf, Evidence: []string{"runs a Java server"}})
		at = len(ms) - 1
	} else {
		ms[at].Confidence = max(ms[at].Confidence, conf)
	}
	j := &ms[at]
	if floor > 0 && (j.Version == "" || (IsFloor(j.Version) && floorOf(j.Version) < floor)) {
		j.Version = floorVersion(floor)
		j.Evidence = union(j.Evidence, []string{why})
	}
	return ms
}

func isJavaServer(p string) bool {
	switch p {
	case Tomcat, Jetty, WildFly, JBoss, WebLogic, GlassFish, Payara, WebSphere, Spring:
		return true
	}
	return false
}
