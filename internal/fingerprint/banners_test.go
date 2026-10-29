package fingerprint

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// The shapes below are trimmed from each engine's documented export format.
// Addresses are from the documentation ranges.

const shodanLine = `{"ip_str":"192.0.2.10","port":443,"data":"HTTP/1.1 302 Found\r\nLocation: /owa/\r\nX-FEServer: EXCH01\r\nX-OWA-Version: 15.1.2507.35\r\nSet-Cookie: ClientId=ABC; path=/\r\n\r\n","http":{"status":302,"title":null,"html":"","location":"/"},"ssl":{"cert":{"subject":{"CN":"mail.example.org"}}}}`

func TestShodanJSONLines(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(shodanLine + "\n" + `{"ip_str":"192.0.2.11","port":22,"data":"SSH-2.0-OpenSSH_9.6"}` + "\n"))
	w.Close()

	bs, err := ReadBanners(&gz, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 1 {
		t.Fatalf("want the one HTTP banner, got %d", len(bs))
	}
	b := bs[0]
	if b.Source != "shodan" || b.Addr != "192.0.2.10:443" || b.Response.Status != 302 {
		t.Errorf("banner %+v", b)
	}
	if b.Response.Headers.Get("Location") != "/owa/" || strings.Join(b.Response.Cookies, ",") != "ClientId" {
		t.Errorf("head parsed wrong: %+v", b.Response)
	}
	if m := top(t, b.Response); m.Product != Exchange || m.Version != "15.1.2507.35" {
		t.Errorf("named %+v", m)
	}
}

func TestShodanSearchResponse(t *testing.T) {
	bs, err := ReadBanners(strings.NewReader(`{"matches":[`+shodanLine+`],"total":1}`), nil)
	if err != nil || len(bs) != 1 {
		t.Fatalf("got %d, %v", len(bs), err)
	}
}

func TestCensysV2(t *testing.T) {
	doc := `{"result":{"hits":[{"ip":"198.51.100.7","services":[
	  {"port":22,"service_name":"SSH"},
	  {"port":443,"service_name":"HTTP","http":{"request":{"uri":"https://198.51.100.7/"},
	   "response":{"status_code":200,"html_title":"Zimbra Web Client Sign In",
	     "headers":{"Set_Cookie":["ZM_TEST=true; Secure"],"Server":["nginx"]},
	     "body":"<html>...</html>"}}}]}]}}`
	bs, err := ReadBanners(strings.NewReader(doc), nil)
	if err != nil || len(bs) != 1 {
		t.Fatalf("got %d, %v", len(bs), err)
	}
	r := bs[0].Response
	if bs[0].Addr != "198.51.100.7:443" || r.Path != "/" || r.Headers.Get("Server") != "nginx" {
		t.Errorf("banner %+v", bs[0])
	}
	if m := top(t, r); m.Product != Zimbra {
		t.Errorf("named %+v", m)
	}
}

func TestCensysPlatform(t *testing.T) {
	doc := `[{"resource":{"ip":"198.51.100.8","services":[{"port":8090,"endpoints":[{"http":{"uri":"http://198.51.100.8:8090/",
	  "status_code":302,"headers":{"X-Confluence-Request-Time":{"headers":["1712"]},"Location":{"headers":["/login.action"]}}}}]}]}}]`
	bs, err := ReadBanners(strings.NewReader(doc), nil)
	if err != nil || len(bs) != 1 {
		t.Fatalf("got %d, %v", len(bs), err)
	}
	if m := top(t, bs[0].Response); m.Product != Confluence {
		t.Errorf("named %+v", m)
	}
}

func TestFOFAArrays(t *testing.T) {
	doc := `{"error":false,"size":1,"results":[["203.0.113.5","443","Kerio Connect Client","HTTP/1.1 200 OK\r\nServer: Kerio Connect 10.0.4\r\n\r\n"]]}`
	bs, err := ReadBanners(strings.NewReader(doc), []string{"ip", "port", "title", "header"})
	if err != nil || len(bs) != 1 {
		t.Fatalf("got %d, %v", len(bs), err)
	}
	if bs[0].Addr != "203.0.113.5:443" {
		t.Errorf("addr %q", bs[0].Addr)
	}
	if m := top(t, bs[0].Response); m.Product != Kerio || m.Version != "10.0.4" {
		t.Errorf("named %+v", m)
	}
}
