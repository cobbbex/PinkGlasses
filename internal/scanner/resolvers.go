package scanner

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Public resolver lists collect thousands of open resolvers, and some of them
// answer for names that do not exist — a captive portal, an ISP's search
// page, an ad injector. A brute force spread over those reports every word in
// the wordlist as a real host. Checking each one first, with a name nothing
// can legitimately answer, removes that at the source.
//
// The check costs one query per resolver, run in parallel with a short
// timeout, so a few hundred resolvers take a couple of seconds.

// checkResolvers keeps the resolvers that answer correctly: a name that
// cannot exist must come back as "no such host". It returns the good ones in
// the order given, and how many were dropped.
func checkResolvers(ctx context.Context, addrs []string, parallel int) (good []string, dropped int) {
	if parallel <= 0 {
		parallel = 32
	}
	probe := randomLabel(12) + "." + randomLabel(10) + ".com"
	ok := make([]bool, len(addrs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok[i] = resolverAnswersHonestly(ctx, addr, probe)
		}(i, addr)
	}
	wg.Wait()
	for i, addr := range addrs {
		if ok[i] {
			good = append(good, addr)
		} else {
			dropped++
		}
	}
	return good, dropped
}

// resolverAnswersHonestly asks one resolver for a name that does not exist.
// "No such host" is the right answer; an address, or no answer at all, is not.
func resolverAnswersHonestly(ctx context.Context, addr, probe string) bool {
	host := addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		host = net.JoinHostPort(addr, "53")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, host)
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := r.LookupHost(cctx, probe)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true // said the name does not exist, which is the truth
	}
	return false // answered with something, or did not answer
}

func randomLabel(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

// vettedResolvers reads a resolver list, checks the resolvers, and writes the
// good ones to a temporary file for the tool that will use them. It returns
// an empty path when the list needs no change or nothing could be checked, so
// a caller falls back to the list it already had.
func vettedResolvers(ctx context.Context, path string, parallel int) (out string, kept, dropped int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, 0, err
	}
	var addrs []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			addrs = append(addrs, l)
		}
	}
	if len(addrs) == 0 {
		return "", 0, 0, nil
	}
	good, dropped := checkResolvers(ctx, addrs, parallel)
	// Every resolver failing means the worker has no DNS egress at all, not
	// that every resolver lies; using an empty list would find nothing, so
	// the caller keeps what it had.
	if len(good) == 0 || dropped == 0 {
		return "", len(good), dropped, nil
	}
	f, err := os.CreateTemp("", "asm-resolvers-ok-*.txt")
	if err != nil {
		return "", 0, 0, err
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(good, "\n") + "\n"); err != nil {
		return "", 0, 0, err
	}
	return f.Name(), len(good), dropped, nil
}
