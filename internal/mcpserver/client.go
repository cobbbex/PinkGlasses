// Package mcpserver is the MCP face of PinkGlasses: a thin adapter over the
// HTTP API, so every rule the web UI obeys — roles, target authorization, exit
// checks, the refusals written for a person — applies unchanged, and every
// action lands in the audit log under the account whose API token was used.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the PinkGlasses API with one bearer token.
type Client struct {
	Base  string // e.g. http://localhost:8080
	Token string // a pgt_ API token
	HTTP  *http.Client
}

// NewClient builds a client for one token.
func NewClient(base, token string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// APIError carries the API's own sentence and status, which the tools pass on
// verbatim: the refusal was written for a person and says what to fix.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string { return e.Msg }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+"/api/v1"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("pinkglasses api: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &APIError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}
func (c *Client) patch(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPatch, path, body, out)
}
func (c *Client) del(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

// getBytes fetches a non-JSON body, such as a screenshot.
func (c *Client) getBytes(ctx context.Context, path string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/api/v1"+path, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 400 {
		return nil, "", &APIError{Status: resp.StatusCode, Msg: strings.TrimSpace(string(data))}
	}
	return data, resp.Header.Get("Content-Type"), nil
}

func q(v string) string { return url.QueryEscape(v) }
