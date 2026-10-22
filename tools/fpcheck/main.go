// Command fpcheck measures the product fingerprints (internal/fingerprint)
// without scanning anybody.
//
// Offline, it reads banners exported from Shodan, Censys or FOFA — responses
// those engines already recorded — and reports, per export, how many the
// rules name as the product the export was searched for:
//
//	fpcheck exchange.json.gz=exchange confluence.json=confluence random.json=none
//
// "=none" marks a sample of unrelated web servers: every product named there
// is a false positive. -fixtures writes matched banners as test cases for
// internal/fingerprint/testdata, and misses beside them for reading.
//
// Live, it fetches one lab instance the way the worker does, front page then
// follow-up probes, and prints what each response showed:
//
//	fpcheck -lab http://127.0.0.1:8090
//
// -lab refuses any address that is not loopback or private. Real targets are
// scanned by the pipeline, against a scope someone authorized.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/benlik386/pinkglasses/internal/fingerprint"
)

func main() {
	lab := flag.String("lab", "", "fetch this lab URL (loopback or private address only) and print what it shows")
	fofaFields := flag.String("fofa-fields", "ip,port,host,title,header,body,server",
		"columns of a FOFA API export whose results are arrays, in query order")
	show := flag.Int("show", 10, "misses (or false positives) to list per export")
	fixtures := flag.String("fixtures", "", "write matched banners here as test fixtures, misses under misses/")
	perFile := flag.Int("fixtures-per-file", 5, "fixtures to write per export")
	asJSON := flag.Bool("json", false, "print the summary as JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: fpcheck [flags] export[=product|none] ...\n       fpcheck -lab http://127.0.0.1:PORT\n\nproducts: %s\n\n",
			strings.Join(fingerprint.Products(), ", "))
		flag.PrintDefaults()
	}
	flag.Parse()

	if *lab != "" {
		if err := runLab(*lab); err != nil {
			fmt.Fprintln(os.Stderr, "fpcheck:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var reports []report
	for _, arg := range flag.Args() {
		rep, err := check(arg, strings.Split(*fofaFields, ","), *show, *fixtures, *perFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fpcheck:", err)
			os.Exit(1)
		}
		reports = append(reports, rep)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(reports)
		return
	}
	for _, r := range reports {
		r.print()
	}
}

type sample struct {
	Addr   string `json:"addr"`
	Status int    `json:"status"`
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	Named  string `json:"named,omitempty"`
}

type report struct {
	File        string         `json:"file"`
	Expect      string         `json:"expect,omitempty"` // product, "none", or "" (just count)
	Banners     int            `json:"banners"`
	Detected    int            `json:"detected"`
	WithVersion int            `json:"with_version"`
	Named       map[string]int `json:"named"`    // every product named, by count
	Versions    map[string]int `json:"versions"` // expected product's versions
	Samples     []sample       `json:"samples"`  // misses, or false positives for "none"
}

func check(arg string, fofaFields []string, show int, fixtureDir string, perFile int) (report, error) {
	path, label, _ := strings.Cut(arg, "=")
	rep := report{File: path, Named: map[string]int{}, Versions: map[string]int{}}
	switch {
	case label == "":
	case strings.EqualFold(label, "none"):
		rep.Expect = "none"
	default:
		if rep.Expect = fingerprint.Lookup(label); rep.Expect == "" {
			return rep, fmt.Errorf("%s: unknown product %q (want one of: %s, or none)",
				path, label, strings.Join(fingerprint.Products(), ", "))
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return rep, err
	}
	defer f.Close()
	banners, err := fingerprint.ReadBanners(f, fofaFields)
	if err != nil {
		return rep, fmt.Errorf("%s: %w", path, err)
	}
	rep.Banners = len(banners)

	written := 0
	for i, b := range banners {
		ms := fingerprint.Settled(fingerprint.Detect(b.Response))
		var names []string
		var hit *fingerprint.Match
		for j, m := range ms {
			rep.Named[m.Product]++
			names = append(names, m.Product)
			if m.Product == rep.Expect {
				hit = &ms[j]
			}
		}
		s := sample{Addr: b.Addr, Status: b.Response.Status, Title: clip(b.Response.Title, 60),
			Server: clip(b.Response.Headers.Get("Server"), 40), Named: strings.Join(names, ", ")}

		switch rep.Expect {
		case "":
			if len(ms) > 0 {
				rep.Detected++
			}
		case "none":
			if len(ms) > 0 {
				rep.Detected++
				if len(rep.Samples) < show {
					rep.Samples = append(rep.Samples, s)
				}
			}
		default:
			if hit != nil {
				rep.Detected++
				if hit.Version != "" {
					rep.WithVersion++
					rep.Versions[hit.Version]++
				}
				if fixtureDir != "" && written < perFile {
					if err := writeFixture(fixtureDir, "", rep.Expect, b, i); err != nil {
						return rep, err
					}
					written++
				}
			} else {
				if len(rep.Samples) < show {
					rep.Samples = append(rep.Samples, s)
				}
				if fixtureDir != "" && len(rep.Samples) <= perFile {
					if err := writeFixture(fixtureDir, "misses", rep.Expect, b, i); err != nil {
						return rep, err
					}
				}
			}
		}
	}
	return rep, nil
}

// fixture is the testdata format: the response and what it should be named.
// The address is not kept — a fixture is a response, not a record of a host.
type fixture struct {
	Source   string               `json:"source"`
	Expect   []string             `json:"expect"`
	Response fingerprint.Response `json:"response"`
}

func writeFixture(dir, sub, product string, b fingerprint.Banner, i int) error {
	dir = filepath.Join(dir, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	alias := strings.ToLower(strings.Fields(product)[len(strings.Fields(product))-1])
	name := filepath.Join(dir, fmt.Sprintf("%s-%s-%04d.json", alias, b.Source, i))
	data, err := json.MarshalIndent(fixture{Source: b.Source, Expect: []string{product}, Response: b.Response}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(name, append(data, '\n'), 0o644)
}

func (r report) print() {
	fmt.Printf("\n== %s", r.File)
	if r.Expect != "" {
		fmt.Printf("  (expect %s)", r.Expect)
	}
	fmt.Printf("\n   banners: %d\n", r.Banners)
	switch r.Expect {
	case "none":
		fmt.Printf("   false positives: %d (%s)\n", r.Detected, pct(r.Detected, r.Banners))
	case "":
		fmt.Printf("   named a product: %d (%s)\n", r.Detected, pct(r.Detected, r.Banners))
	default:
		fmt.Printf("   detected: %d (%s), with version: %d (%s of detected)\n",
			r.Detected, pct(r.Detected, r.Banners), r.WithVersion, pct(r.WithVersion, r.Detected))
	}
	if len(r.Named) > 0 {
		fmt.Println("   named:")
		for _, k := range sortedKeys(r.Named) {
			fmt.Printf("     %-22s %d\n", k, r.Named[k])
		}
	}
	if len(r.Versions) > 0 {
		fmt.Println("   versions:")
		for _, k := range sortedKeys(r.Versions) {
			fmt.Printf("     %-22s %d\n", k, r.Versions[k])
		}
	}
	if len(r.Samples) > 0 {
		if r.Expect == "none" {
			fmt.Println("   false positives:")
		} else {
			fmt.Println("   missed:")
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, s := range r.Samples {
			fmt.Fprintf(w, "     %s\t%d\t%s\t%s\t%s\n", s.Addr, s.Status, s.Server, s.Title, s.Named)
		}
		w.Flush()
	}
}

// --- lab ---

func runLab(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-lab wants http(s)://host[:port], got %q", raw)
	}
	addrs, err := net.LookupIP(u.Hostname())
	if err != nil {
		return err
	}
	for _, ip := range addrs {
		if !(ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("%s resolves to %s: -lab fetches only loopback and private addresses; scan real targets through the pipeline, against an authorized scope", u.Hostname(), ip)
		}
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	f := fingerprint.Fetcher{Client: client, UserAgent: "pinkglasses-fpcheck", Timeout: 15 * time.Second}
	res, err := f.Run(context.Background(), u.Scheme+"://"+u.Host)
	if err != nil {
		return err
	}
	for _, r := range res.Responses {
		fmt.Printf("GET %-45s %d  %q", r.Path, r.Status, clip(r.Title, 50))
		if loc := r.Headers.Get("Location"); loc != "" {
			fmt.Printf("  -> %s", clip(loc, 80))
		}
		fmt.Println()
		for _, m := range fingerprint.Detect(r) {
			fmt.Printf("    %-22s %3d  %s\n", m.Product, m.Confidence, strings.Join(m.Evidence, "; "))
		}
	}
	fmt.Println("\nresult:")
	if len(res.Matches) == 0 {
		fmt.Println("  nothing named")
	}
	for _, m := range res.Matches {
		fmt.Printf("  %s %s", m.Product, m.Version)
		if m.Release != "" {
			fmt.Printf(" (%s)", m.Release)
		}
		fmt.Printf("  confidence %d", m.Confidence)
		if len(m.Features) > 0 {
			fmt.Printf("  [%s]", strings.Join(m.Features, ", "))
		}
		fmt.Println()
	}
	return nil
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
