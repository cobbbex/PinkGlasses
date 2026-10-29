package sshexit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Endpoint is one VPS to hold a session to.
type Endpoint struct {
	Host       string
	Port       int
	User       string
	PrivateKey []byte
	// HostKey is the pinned SHA256 fingerprint, "" before first contact.
	HostKey string
}

// ErrHostKeyChanged means the VPS presented a key other than the one pinned:
// it was rebuilt, or something is in the way. Either way the connector stops
// and says so rather than handing a stranger a worker's enrolment token.
var ErrHostKeyChanged = errors.New("host key changed")

// Dial opens a session. On first contact (no HostKey) the presented key is
// passed to pin before the session is used; after that only the pinned key
// is accepted.
func Dial(ctx context.Context, ep Endpoint, pin func(fingerprint string) error) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(ep.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:    ep.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if ep.HostKey == "" {
				return pin(fp)
			}
			if fp != ep.HostKey {
				return fmt.Errorf("%w: pinned %s, the server presented %s — if the VPS was rebuilt, delete this exit and add it again",
					ErrHostKeyChanged, ep.HostKey, fp)
			}
			return nil
		},
	}
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// Forward asks the VPS to listen on its loopback at remotePort and carries
// every connection it accepts to local (host:port on this side). It returns
// once listening, with a function that stops it; errc receives the reason
// the listener ended.
func Forward(client *ssh.Client, remotePort int, local string) (stop func(), errc <-chan error, err error) {
	ln, err := client.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)))
	if err != nil {
		return nil, nil, fmt.Errorf("the VPS refused to listen on 127.0.0.1:%d (in use, or AllowTcpForwarding is off in its sshd_config): %v", remotePort, err)
	}
	ch := make(chan error, 1)
	go func() {
		for {
			remote, err := ln.Accept()
			if err != nil {
				ch <- err
				return
			}
			go splice(remote, local)
		}
	}()
	return func() { ln.Close() }, ch, nil
}

func splice(remote net.Conn, local string) {
	defer remote.Close()
	l, err := net.DialTimeout("tcp", local, 10*time.Second)
	if err != nil {
		return
	}
	defer l.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Half-close so the other side sees EOF, as a TCP proxy should.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(l, remote)
	go cp(remote, l)
	wg.Wait()
}

// KeepAlive pings the server every interval and closes the client when a
// ping goes unanswered, which is what ends a session to a VPS that vanished
// without a FIN. It returns when the client closes or ctx ends.
func KeepAlive(ctx context.Context, client *ssh.Client, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			done := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					client.Close()
					return
				}
			case <-time.After(interval):
				client.Close()
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// Run executes a script on the VPS through sh and returns what it printed,
// stdout and stderr together, capped.
func Run(ctx context.Context, client *ssh.Client, script string, timeout time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out capped
	out.max = 64 << 10
	sess.Stdout, sess.Stderr = &out, &out
	sess.Stdin = bytes.NewReader([]byte(script))
	done := make(chan error, 1)
	go func() { done <- sess.Run("sh -s") }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = sess.Signal(ssh.SIGKILL)
		return out.String(), fmt.Errorf("timed out after %s", timeout)
	case <-ctx.Done():
		return out.String(), ctx.Err()
	}
}

// capped is a buffer that keeps the first max bytes, safe for two writers.
type capped struct {
	mu  sync.Mutex
	b   bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}
