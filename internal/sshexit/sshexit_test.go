package sshexit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is a minimal sshd: public-key auth, "tcpip-forward" (what
// ssh -R asks for) and "exec", which echoes the script it is sent. Enough to
// exercise everything the connector does without a VPS.
type testServer struct {
	addr    string
	hostKey ssh.Signer
	ln      net.Listener
	mu      sync.Mutex
	scripts []string
}

func newTestServer(t *testing.T, authorized ssh.PublicKey) *testServer {
	t.Helper()
	priv, _, err := GenerateKey("host")
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{addr: ln.Addr().String(), hostKey: hk, ln: ln}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(hk)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *testServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				var p struct {
					Addr string
					Port uint32
				}
				_ = ssh.Unmarshal(req.Payload, &p)
				ln, err := net.Listen("tcp", net.JoinHostPort(p.Addr, strconv.Itoa(int(p.Port))))
				if err != nil {
					req.Reply(false, nil)
					continue
				}
				go func() { <-done(conn); ln.Close() }()
				go s.acceptForwarded(conn, ln, p.Addr, p.Port)
				req.Reply(true, nil)
			case "keepalive@openssh.com":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, _ := nc.Accept()
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				script, _ := io.ReadAll(ch)
				s.mu.Lock()
				s.scripts = append(s.scripts, string(script))
				s.mu.Unlock()
				fmt.Fprintf(ch, "ran %d bytes\n", len(script))
				status := make([]byte, 4)
				if strings.Contains(string(script), "exit 7") {
					fmt.Fprintln(ch, "PG-ERR: told to fail")
					binary.BigEndian.PutUint32(status, 7)
				}
				ch.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
}

func done(c *ssh.ServerConn) <-chan struct{} {
	ch := make(chan struct{})
	go func() { c.Wait(); close(ch) }()
	return ch
}

func (s *testServer) acceptForwarded(conn *ssh.ServerConn, ln net.Listener, addr string, port uint32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			ra := c.RemoteAddr().(*net.TCPAddr)
			payload := ssh.Marshal(struct {
				Addr       string
				Port       uint32
				OriginAddr string
				OriginPort uint32
			}{addr, port, ra.IP.String(), uint32(ra.Port)})
			ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			go func() { io.Copy(ch, c); ch.CloseWrite() }()
			io.Copy(c, ch)
		}()
	}
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func endpoint(t *testing.T, s *testServer, key []byte) Endpoint {
	host, port, _ := net.SplitHostPort(s.addr)
	p, _ := strconv.Atoi(port)
	return Endpoint{Host: host, Port: p, User: "root", PrivateKey: key}
}

func setup(t *testing.T) (*testServer, []byte) {
	key, _, err := GenerateKey("test")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.ParsePrivateKey(key)
	return newTestServer(t, signer.PublicKey()), key
}

// First contact pins the host key; after that only that key is accepted.
func TestDialPinsThenEnforcesHostKey(t *testing.T) {
	s, key := setup(t)
	ep := endpoint(t, s, key)
	var pinned string
	c, err := Dial(context.Background(), ep, func(fp string) error { pinned = fp; return nil })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if pinned != ssh.FingerprintSHA256(s.hostKey.PublicKey()) {
		t.Fatalf("pinned %q", pinned)
	}

	ep.HostKey = pinned
	c, err = Dial(context.Background(), ep, func(string) error { t.Fatal("pinned again"); return nil })
	if err != nil {
		t.Fatalf("the pinned key was refused: %v", err)
	}
	c.Close()

	ep.HostKey = "SHA256:somebody-else"
	if _, err := Dial(context.Background(), ep, nil); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("a different host key was accepted: %v", err)
	}
}

func TestDialRefusesUnknownClientKey(t *testing.T) {
	s, _ := setup(t)
	other, _, _ := GenerateKey("other")
	if _, err := Dial(context.Background(), endpoint(t, s, other), func(string) error { return nil }); err == nil {
		t.Fatal("a key the server does not know was let in")
	}
}

// What the worker on the VPS sends to its loopback arrives at the gateway
// on this side, and the answer goes back.
func TestForwardCarriesConnectionsBack(t *testing.T) {
	s, key := setup(t)
	gw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	go func() {
		for {
			c, err := gw.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 5)
				io.ReadFull(c, b)
				c.Write([]byte("gateway got " + string(b)))
			}()
		}
	}()

	client, err := Dial(context.Background(), endpoint(t, s, key), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	port := freePort(t)
	stop, _, err := Forward(client, port, gw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// "the worker": connect to the VPS's loopback port
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != "gateway got hello" {
		t.Fatalf("got %q", got)
	}
}

func TestRunReturnsOutputAndFailure(t *testing.T) {
	s, key := setup(t)
	client, err := Dial(context.Background(), endpoint(t, s, key), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	out, err := Run(context.Background(), client, "echo hi\n", 10*time.Second)
	if err != nil || !strings.Contains(out, "ran 8 bytes") {
		t.Fatalf("out %q err %v", out, err)
	}
	out, err = Run(context.Background(), client, "exit 7\n", 10*time.Second)
	if err == nil || FailureReason(out) != "told to fail" {
		t.Fatalf("out %q err %v", out, err)
	}
}

// The script is the one place a value lands in a shell on someone else's
// server: anything not the expected shape is refused before it gets there.
func TestScriptRefusesAnythingShellShaped(t *testing.T) {
	ok := InstallSpec{Image: "ghcr.io/cobbbex/pinkglasses-worker:latest", Token: strings.Repeat("a", 43),
		WorkerName: "vps-1", GatewayPort: 47090, StoreHost: "minio"}
	script, err := Script(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--network host", "--add-host 'minio:127.0.0.1'",
		"ASM_GATEWAY_URL='http://127.0.0.1:47090'", "--restart unless-stopped"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	bad := []InstallSpec{
		{Image: "x'; rm -rf /; '", Token: ok.Token, WorkerName: "a", GatewayPort: 47090},
		{Image: ok.Image, Token: "$(id)aaaaaaaaaaaaaaaa", WorkerName: "a", GatewayPort: 47090},
		{Image: ok.Image, Token: ok.Token, WorkerName: "a b", GatewayPort: 47090},
		{Image: ok.Image, Token: ok.Token, WorkerName: "a", GatewayPort: 22},
		{Image: ok.Image, Token: ok.Token, WorkerName: "a", GatewayPort: 47090, StoreHost: "x;y"},
	}
	for i, b := range bad {
		if _, err := Script(b); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

func TestAuthorizedLineRefusesPassphraseKeys(t *testing.T) {
	priv, line, err := GenerateKey("c")
	if err != nil || !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, " c") {
		t.Fatalf("line %q err %v", line, err)
	}
	if got, _ := AuthorizedLine(priv, "c"); got != line {
		t.Errorf("round trip %q != %q", got, line)
	}
	if _, err := AuthorizedLine([]byte("not a key"), ""); err == nil {
		t.Error("garbage accepted")
	}
}

func TestValidators(t *testing.T) {
	for _, h := range []string{"vps.example.org", "203.0.113.5", "2001:db8::1"} {
		if !ValidHost(h) {
			t.Errorf("%s refused", h)
		}
	}
	for _, h := range []string{"-oProxyCommand=x", "a b", "x;y", ""} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
	if !ValidUser("ubuntu") || ValidUser("-x") || ValidUser("root;id") {
		t.Error("user validation")
	}
}
