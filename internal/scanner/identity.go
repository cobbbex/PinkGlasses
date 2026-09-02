package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"

	"github.com/benlik386/pinkglasses/internal/scanparams"
	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// How the scan presents itself on the wire: the User-Agent every web request
// carries, and the proxy it goes out through.

// userAgent returns the User-Agent for this job's web requests.
//
// The default is a mobile browser rather than a tool string. A scanner that
// announces itself is trivially filtered, and plenty of sites serve a reduced
// page to anything that does — which shows up as missing findings, not as an
// error.
func userAgent(pr params) string {
	return pr.str("httpx_user_agent", defaultUserAgent)
}

const defaultUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) " +
	"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

// proxyFor picks this job's proxy from the configured list.
//
// One proxy per task, chosen by hashing the target: stable, so retrying a task
// reuses the same egress and a result stays reproducible, but spread across the
// list, so a run with several proxies leaves through several addresses instead
// of pinning everything to the first one.
func proxyFor(job scanproto.Job, pr params) string {
	list := scanparams.ParseProxies(pr.str("httpx_proxy", ""))
	if len(list) == 0 {
		return ""
	}
	if len(list) == 1 {
		return list[0]
	}
	sum := sha256.Sum256([]byte(describeTarget(job)))
	return list[binary.BigEndian.Uint64(sum[:8])%uint64(len(list))]
}

// proxyUsableBy reports whether a tool can actually use this proxy. httpx takes
// http and socks; gobuster and katana document http(s) and socks5 only, and
// handing either a socks4 URL fails the whole invocation rather than degrading.
func proxyUsableBy(tool, raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch tool {
	case "httpx":
		return true
	default:
		return u.Scheme != "socks4"
	}
}

// proxyTransport builds a transport that dials through the given proxy, for the
// pure-Go fallbacks. socks4 has no support in the standard library or x/net, so
// a socks4 proxy is reported and the request goes direct rather than silently
// leaving from the worker's own address.
func proxyTransport(base *http.Transport, raw string) *http.Transport {
	if raw == "" {
		return base
	}
	u, err := url.Parse(raw)
	if err != nil {
		return base
	}
	switch u.Scheme {
	case "http", "https":
		base.Proxy = http.ProxyURL(u)
		return base
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			slog.Warn("could not use socks5 proxy; scanning direct", "proxy", u.Host, "err", err)
			return base
		}
		base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		}
		return base
	default:
		slog.Warn("proxy scheme not supported by the built-in prober; scanning direct",
			"scheme", u.Scheme, "note", "the external tools may still use it")
		return base
	}
}

// logProxy records the egress a stage used, so a result can be traced back to
// the address it was collected from.
func logProxy(stage, tool, raw string) {
	if raw == "" {
		return
	}
	if u, err := url.Parse(raw); err == nil {
		// Never log credentials.
		slog.Info("scanning through proxy", "stage", stage, "tool", tool,
			"proxy", u.Scheme+"://"+u.Host)
		return
	}
	slog.Info("scanning through proxy", "stage", stage, "tool", tool,
		"proxy", strings.SplitN(raw, "@", 2)[len(strings.SplitN(raw, "@", 2))-1])
}
