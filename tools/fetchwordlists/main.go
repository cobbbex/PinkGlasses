// Command fetchwordlists downloads the shipped wordlists at image build time
// into a directory the control-plane image carries, gzip-compressed, so a
// fresh deployment has every list without reaching the internet at runtime.
//
//	go run ./tools/fetchwordlists /out
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/benlik386/pinkglasses/internal/wordlists/builtin"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fetchwordlists <outdir>")
		os.Exit(2)
	}
	out := os.Args[1]
	if err := os.MkdirAll(out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	for _, l := range builtin.Lists {
		dst := builtin.BundleFile(out, l.ObjectKey)
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			fmt.Printf("have  %s\n", dst)
			continue
		}
		var lastErr error
		for attempt := 1; attempt <= 3; attempt++ {
			if lastErr = fetch(client, l.SourceURL, dst); lastErr == nil {
				break
			}
			fmt.Fprintf(os.Stderr, "retry %d for %s: %v\n", attempt, l.Name, lastErr)
			time.Sleep(time.Duration(attempt*5) * time.Second)
		}
		if lastErr != nil {
			fmt.Fprintf(os.Stderr, "could not fetch %s: %v\n", l.Name, lastErr)
			os.Exit(1)
		}
	}
}

func fetch(client *http.Client, url, dst string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	tmp := dst + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	n, err := io.Copy(gz, resp.Body)
	if err == nil {
		err = gz.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if n == 0 {
		os.Remove(tmp)
		return fmt.Errorf("empty file")
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	fmt.Printf("fetch %s (%d bytes) -> %s\n", url, n, dst)
	return nil
}
