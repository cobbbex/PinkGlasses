package obj

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Usage is what the bucket holds, split by what wrote it: screenshots belong
// to scan history, wordlists to the install. Reported so an operator can
// watch storage grow and decide about it, rather than discovering a full disk.
type Usage struct {
	TotalBytes int64            `json:"total_bytes"`
	Objects    int              `json:"objects"`
	ByPrefix   map[string]int64 `json:"by_prefix"` // top-level folder -> bytes
	CountBy    map[string]int   `json:"count_by"`  // top-level folder -> objects
	Truncated  bool             `json:"truncated"` // stopped at the page cap
}

// listMaxPages caps a sweep at a million objects. Past that the number is
// reported as a lower bound rather than held for minutes.
const listMaxPages = 1000

// Usage lists the bucket and sums it. One request per thousand objects, so the
// caller caches the answer rather than asking on every page load.
func (s *Store) Usage(ctx context.Context) (Usage, error) {
	u := Usage{ByPrefix: map[string]int64{}, CountBy: map[string]int{}}
	token := ""
	for page := 0; page < listMaxPages; page++ {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("max-keys", "1000")
		if token != "" {
			q.Set("continuation-token", token)
		}
		signed, err := s.presignWith(http.MethodGet, "", q, time.Minute, time.Now())
		if err != nil {
			return u, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, signed, nil)
		if err != nil {
			return u, err
		}
		resp, err := listClient.Do(req)
		if err != nil {
			return u, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return u, err
		}
		if resp.StatusCode >= 300 {
			return u, fmt.Errorf("list bucket: %s", resp.Status)
		}
		var out struct {
			IsTruncated bool   `xml:"IsTruncated"`
			NextToken   string `xml:"NextContinuationToken"`
			Contents    []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &out); err != nil {
			return u, err
		}
		for _, o := range out.Contents {
			u.TotalBytes += o.Size
			u.Objects++
			top := "other"
			if i := strings.Index(o.Key, "/"); i > 0 {
				top = o.Key[:i]
			}
			u.ByPrefix[top] += o.Size
			u.CountBy[top]++
		}
		if !out.IsTruncated || out.NextToken == "" {
			return u, nil
		}
		token = out.NextToken
	}
	u.Truncated = true
	return u, nil
}

var listClient = &http.Client{Timeout: 30 * time.Second}
