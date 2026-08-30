// Package obj is a minimal S3/MinIO client that produces presigned PUT/GET URLs
// using AWS Signature V4. Workers upload raw tool output and screenshots
// directly to object storage via these URLs, so artifacts never transit the
// gateway (architecture.md §3.2). Implemented with the stdlib to avoid pulling
// the full AWS SDK.
package obj

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/benlik386/asm/internal/config"
)

// Store presigns object-storage operations.
type Store struct {
	cfg config.S3
}

// New builds an object store client.
func New(cfg config.S3) *Store { return &Store{cfg: cfg} }

// PresignPut returns a URL a worker can PUT an artifact to, valid for expiry.
func (s *Store) PresignPut(key string, expiry time.Duration, now time.Time) (string, error) {
	return s.presign("PUT", key, expiry, now)
}

// PresignGet returns a URL to download an artifact, valid for expiry.
func (s *Store) PresignGet(key string, expiry time.Duration, now time.Time) (string, error) {
	return s.presign("GET", key, expiry, now)
}

func (s *Store) presign(method, key string, expiry time.Duration, now time.Time) (string, error) {
	u, err := url.Parse(s.cfg.Endpoint)
	if err != nil {
		return "", err
	}
	host := u.Host
	scheme := u.Scheme
	region := s.cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	key = strings.TrimPrefix(key, "/")
	canonicalURI := "/" + s.cfg.Bucket + "/" + uriEncodePath(key)

	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	credentialScope := dateStamp + "/" + region + "/s3/aws4_request"

	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", s.cfg.AccessKey+"/"+credentialScope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", int(expiry.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")

	canonicalQuery := encodeQuerySorted(q)
	canonicalHeaders := "host:" + host + "\n"
	canonicalRequest := strings.Join([]string{
		method, canonicalURI, canonicalQuery, canonicalHeaders, "host", "UNSIGNED-PAYLOAD",
	}, "\n")

	hashedCR := sha256Hex([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, hashedCR,
	}, "\n")

	signingKey := deriveKey(s.cfg.SecretKey, dateStamp, region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	return fmt.Sprintf("%s://%s%s?%s&X-Amz-Signature=%s",
		scheme, host, canonicalURI, canonicalQuery, signature), nil
}

func deriveKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func encodeQuerySorted(q url.Values) string {
	// url.Values.Encode already sorts by key and encodes per RFC 3986 mostly;
	// S3 requires space as %20, which Encode does. Good enough for our keys.
	return q.Encode()
}

func uriEncodePath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}
