package fingerprint

import (
	"net/http"
	"testing"
)

func TestJavaVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.8": "8", "1.8.0_392": "8u392", "1.7.0_80": "7u80", "17.0.9": "17.0.9",
		"11.0.21+9": "11.0.21", "21": "21",
	} {
		if got := javaVersion(in); got != want {
			t.Errorf("javaVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJavaFloor(t *testing.T) {
	cases := []struct {
		product, version string
		want             int
	}{
		{Tomcat, "11.0.2", 17}, {Tomcat, "10.1.34", 11}, {Tomcat, "10.0.27", 8},
		{Tomcat, "9.0.98", 8}, {Tomcat, "8.5.100", 7}, {Tomcat, "7.0.109", 6},
		{Jetty, "12.0.16", 17}, {Jetty, "11.0.24", 11}, {Jetty, "9.4.56.v20240826", 8},
		{Jetty, "9.2.30.v20200428", 7},
		{WildFly, "35.0.0.Final", 17}, {WildFly, "31.0.1.Final", 11}, {WildFly, "10", 8},
		{GlassFish, "7.0.11", 11}, {GlassFish, "4.1.2", 7}, {Payara, "5.2022.5", 8},
		{WebLogic, "14.1.1.0.0", 8}, {WebLogic, "14.1.2.0.0", 17}, {WebLogic, "12.2.1.4.0", 8},
		{WebLogic, "12.1.3.0.0", 7}, {WebLogic, "10.3.6.0", 6},
		{WebSphere, "9.0", 8}, {WebSphere, "8.5", 6},
		{Tomcat, "", 0}, {Spring, "", 0},
	}
	for _, c := range cases {
		if got := javaFloor(c.product, c.version); got != c.want {
			t.Errorf("javaFloor(%s %s) = %d, want %d", c.product, c.version, got, c.want)
		}
	}
}

func TestInferJava(t *testing.T) {
	// A named server is Java, at least the release it needs.
	ms := InferJava([]Match{{Product: Tomcat, Version: "10.1.34", Confidence: 97}})
	j := find(ms, Java)
	if j == nil || j.Version != "11+" || j.Confidence != 97 {
		t.Fatalf("Tomcat 10.1 gave Java %+v", j)
	}
	// A version stated outright is kept.
	ms = InferJava([]Match{{Product: Payara, Version: "5.2022.5", Confidence: 97},
		{Product: Java, Version: "8u392", Confidence: 97}})
	if j := find(ms, Java); j.Version != "8u392" {
		t.Errorf("stated version replaced: %+v", j)
	}
	// Nothing Java-ish named, nothing added.
	if ms := InferJava([]Match{{Product: Exchange, Confidence: 99}}); find(ms, Java) != nil {
		t.Errorf("Java inferred from Exchange")
	}
}

func find(ms []Match, p string) *Match {
	for i := range ms {
		if ms[i].Product == p {
			return &ms[i]
		}
	}
	return nil
}

func TestJavaRules(t *testing.T) {
	cases := []struct {
		name     string
		r        Response
		product  string
		version  string
		features []string
	}{
		{"tomcat 404", Response{Path: javaNotFound, Status: 404, Title: "HTTP Status 404 – Not Found",
			Body: `<h1>HTTP Status 404 – Not Found</h1><hr class="line" /><h3>Apache Tomcat/9.0.98</h3>`},
			Tomcat, "9.0.98", nil},
		{"tomcat manager realm", Response{Path: "/manager/html", Status: 401,
			Headers: http.Header{"Www-Authenticate": {`Basic realm="Tomcat Manager Application"`}}},
			Tomcat, "", []string{"Manager"}},
		{"jetty server header", Response{Status: 200, Headers: http.Header{"Server": {"Jetty(9.4.56.v20240826)"}}},
			Jetty, "9.4.56.v20240826", nil},
		{"jetty error page", Response{Status: 404, Body: `<a href="https://jetty.org/">Powered by Jetty:// 12.0.16</a>`},
			Jetty, "12.0.16", nil},
		{"weblogic 404", Response{Status: 404, Title: "Error 404--Not Found",
			Body: `<H2>Error 404--Not Found</H2><H3>From RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1:</H3>`},
			WebLogic, "", nil},
		{"weblogic console", Response{Path: "/console/login/LoginForm.jsp", Status: 200,
			Title: "Oracle WebLogic Server Administration Console 12c", Cookies: []string{"ADMINCONSOLESESSION"},
			Body: `<p id="footerVersion">WebLogic Server Version: 12.2.1.4.0</p>`},
			WebLogic, "12.2.1.4.0", []string{"Console"}},
		{"payara header", Response{Status: 200, Headers: http.Header{
			"Server":       {"Payara Server  5.2022.5 #badassfish"},
			"X-Powered-By": {"Servlet/4.0 JSP/2.3 (Payara Server  5.2022.5 #badassfish Java/Azul Systems, Inc./1.8)"}}},
			Payara, "5.2022.5", nil},
		{"websphere liberty 404", Response{Status: 404,
			Body: `Error 404: java.io.FileNotFoundException: SRVE0190E: File not found: /x.jsp`},
			WebSphere, "", nil},
		{"spring whitelabel", Response{Status: 404, Title: "",
			Body: `<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>`},
			Spring, "", nil},
		{"spring actuator", Response{Path: "/actuator", Status: 200,
			Headers: http.Header{"Content-Type": {"application/vnd.spring-boot.actuator.v3+json"}},
			Body:    `{"_links":{"self":{"href":"http://x/actuator","templated":false},"health":{"href":"http://x/actuator/health","templated":false},"env":{"href":"http://x/actuator/env","templated":false},"heapdump":{"href":"http://x/actuator/heapdump","templated":false}}}`},
			Spring, "", []string{"Actuator", "Actuator env", "Actuator heapdump"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.r.Headers == nil {
				c.r.Headers = http.Header{}
			}
			m := find(Settled(Detect(c.r)), c.product)
			if m == nil {
				t.Fatalf("%s not named; detect gave %+v", c.product, Detect(c.r))
			}
			if m.Version != c.version {
				t.Errorf("version %q, want %q", m.Version, c.version)
			}
			for _, f := range c.features {
				found := false
				for _, g := range m.Features {
					found = found || g == f
				}
				if !found {
					t.Errorf("feature %q missing from %v", f, m.Features)
				}
			}
		})
	}
	// Payara's header states Java outright.
	r := Response{Status: 200, Headers: http.Header{"X-Powered-By": {"Servlet/4.0 JSP/2.3 (Payara Server  5.2022.5 #badassfish Java/Azul Systems, Inc./1.8)"}}}
	if j := find(Detect(r), Java); j == nil || j.Version != "8" {
		t.Errorf("Java from X-Powered-By: %+v", j)
	}
	// Payara is not also GlassFish.
	if find(Settled(Detect(r)), GlassFish) != nil {
		t.Errorf("Payara named GlassFish too")
	}
	// A lone JSESSIONID names Java and nothing else.
	r = Response{Status: 200, Headers: http.Header{}, Cookies: []string{"JSESSIONID"}}
	ms := Settled(Detect(r))
	if len(ms) != 1 || ms[0].Product != Java {
		t.Errorf("JSESSIONID named %+v", ms)
	}
}
