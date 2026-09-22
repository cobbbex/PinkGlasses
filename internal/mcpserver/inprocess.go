package mcpserver

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// NewInProcessClient is a Client whose requests never leave the process: they
// are handed straight to the api's own router, as if they had arrived on the
// wire, token and all. This is how the api serves MCP itself at /mcp — one
// container, one port, no second service to deploy or point at the first.
// Every rule the API applies still applies, because it is the API answering.
func NewInProcessClient(routes http.Handler, token string) *Client {
	return &Client{
		Base:  "http://pinkglasses.internal",
		Token: token,
		HTTP:  &http.Client{Timeout: 60 * time.Second, Transport: handlerTransport{h: routes}},
	}
}

// handlerTransport is an http.RoundTripper that serves a request with a
// handler and returns what it wrote.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The router sees a request from the loopback: no proxy headers, no
	// forwarded address, exactly what a local caller would present.
	req = req.Clone(req.Context())
	req.RemoteAddr = "127.0.0.1:0"
	req.RequestURI = req.URL.RequestURI()
	rec := &recorder{hdr: http.Header{}, code: http.StatusOK}
	t.h.ServeHTTP(rec, req)
	return &http.Response{
		Status:        http.StatusText(rec.code),
		StatusCode:    rec.code,
		Header:        rec.hdr,
		Body:          io.NopCloser(bytes.NewReader(rec.body.Bytes())),
		ContentLength: int64(rec.body.Len()),
		Request:       req,
	}, nil
}

// recorder is the http.ResponseWriter the handler writes into.
type recorder struct {
	hdr  http.Header
	code int
	body bytes.Buffer
	sent bool
}

func (r *recorder) Header() http.Header { return r.hdr }
func (r *recorder) WriteHeader(code int) {
	if !r.sent {
		r.code = code
		r.sent = true
	}
}
func (r *recorder) Write(b []byte) (int, error) {
	r.sent = true
	return r.body.Write(b)
}
