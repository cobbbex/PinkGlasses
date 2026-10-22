package scanner

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/benlik386/pinkglasses/internal/fingerprint"
	"github.com/benlik386/pinkglasses/internal/scanproto"
)

// productObservations names the edge products breaches most often start from
// — NetScaler, Confluence, Jira, Zammad, Zimbra, Exchange, Kerio Connect — on
// one site, with a version where the site gives one away. It asks for the
// front page and at most fingerprint.MaxProbes fixed paths, and only paths of
// a product the front page already resembles; a redirect is followed only
// while it stays on the same name. The pages it read are also searched for
// PHP error messages, which become a finding.
//
// `named` holds what httpx's fingerprint already reported. A product it named
// is still reported here when this found a version, since the store keeps the
// more precise row.
func productObservations(ctx context.Context, job scanproto.Job, pr params, url string, named map[string]bool) []scanproto.Observation {
	if !pr.boolVal("product_fingerprint", true) || url == "" {
		return nil
	}
	ip, port := targetIPPort(job)
	host := targetHost(job)
	f := fingerprint.Fetcher{
		Client:    proxiedClient(proxyFor(job, pr)),
		UserAgent: userAgent(pr),
		Delay:     time.Duration(pr.intVal("httpx_delay_s", 1)) * time.Second,
	}
	res, err := f.Run(ctx, url)
	if err != nil {
		return nil
	}
	var obs []scanproto.Observation
	tech := func(name, version string, confidence int) {
		obs = append(obs, scanproto.Observation{
			Type: scanproto.ObsTech, IP: ip, Port: port, Host: host,
			TechName: name, TechVersion: version, TechConfidence: confidence,
		})
	}
	// The same pages, read for PHP error messages: one finding per site,
	// from the first page that shows one.
	for _, r := range res.Responses {
		if errs := phpErrors(r.Body); len(errs) > 0 {
			obs = append(obs, phpErrorObservations(ip, port, host, strings.TrimRight(url, "/")+r.Path, errs)...)
			break
		}
	}
	for _, m := range res.Matches {
		slog.Info("product", "url", url, "product", m.Product, "version", m.Version,
			"confidence", m.Confidence, "features", m.Features, "evidence", m.Evidence)
		if !named[strings.ToLower(m.Product)] || m.Version != "" {
			tech(m.Product, m.Version, m.Confidence)
		}
		if m.Release != "" {
			tech(m.Release, m.Version, m.Confidence)
		}
		// A feature is its own technology so the inventory can be searched
		// for it: "every NetScaler Gateway with SAML in front of it".
		for _, feat := range m.Features {
			tech(m.Product+" "+feat, "", m.Confidence)
		}
	}
	return obs
}
