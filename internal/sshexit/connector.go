package sshexit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/benlik386/pinkglasses/internal/store"
)

// Store is the part of the database the connector uses.
type Store interface {
	SSHExitSessions(ctx context.Context) ([]store.SSHExitSession, error)
	SetSSHExitState(ctx context.Context, id uuid.UUID, status string, lastErr, remoteAddr *string) error
	PinSSHExitHostKey(ctx context.Context, id uuid.UUID, fingerprint string) error
	StartSSHExitInstall(ctx context.Context, id uuid.UUID) (bool, error)
	FinishSSHExitInstall(ctx context.Context, id uuid.UUID, ok bool, log string) error
	DeleteSSHExit(ctx context.Context, id uuid.UUID) error
	CreatePreapprovedEnrollmentToken(ctx context.Context, hash []byte, poolID *uuid.UUID, ttl time.Duration, egress *string) error
}

// Config for the connector.
type Config struct {
	Gateway     string        // host:port of the gateway on this side
	Store       string        // host:port of the object store on this side, "" for none
	StoreHost   string        // the store's host name in presigned URLs
	StorePort   int           // and its port, which the VPS listens on too
	WorkerImage string        // what the VPS pulls
	Poll        time.Duration // how often the table is read
	KeepAlive   time.Duration
}

// Manager holds one session per exit and reconciles them with the table.
type Manager struct {
	st  Store
	cfg Config

	mu   sync.Mutex
	live map[uuid.UUID]*held
}

// held is one exit's session goroutine and what it currently has.
type held struct {
	cancel  context.CancelFunc
	conf    string // the fields that, changed, mean a new session
	mu      sync.Mutex
	client  *ssh.Client
	remote  string // the address the session reached
	busy    bool   // an install or removal is running
	stopped chan struct{}
}

// New makes a manager.
func New(st Store, cfg Config) *Manager {
	if cfg.Poll == 0 {
		cfg.Poll = 3 * time.Second
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 15 * time.Second
	}
	return &Manager{st: st, cfg: cfg, live: map[uuid.UUID]*held{}}
}

// Run reconciles until ctx ends, then closes every session.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	for {
		if err := m.reconcile(ctx); err != nil {
			slog.Warn("could not read the SSH exits", "err", err)
		}
		select {
		case <-ctx.Done():
			m.mu.Lock()
			for id, h := range m.live {
				h.cancel()
				delete(m.live, id)
			}
			m.mu.Unlock()
			return nil
		case <-t.C:
		}
	}
}

func confKey(e store.SSHExitSession) string {
	hk := ""
	if e.HostKey != nil {
		hk = *e.HostKey
	}
	return fmt.Sprintf("%s|%d|%s|%d|%x|%s", e.Host, e.Port, e.Username, e.RemotePort, sha256.Sum256(e.PrivateKey), hk)
}

func (m *Manager) reconcile(ctx context.Context) error {
	exits, err := m.st.SSHExitSessions(ctx)
	if err != nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range exits {
		seen[e.ID] = true
		h := m.live[e.ID]
		key := confKey(e)
		// A pinned host key appearing is the session's own doing, not a
		// change of configuration; anything else restarts the session.
		if h != nil && h.conf != key && !onlyPinned(h.conf, key) {
			h.cancel()
			delete(m.live, e.ID)
			h = nil
		}
		if h == nil && !e.Deleting {
			hctx, cancel := context.WithCancel(ctx)
			h = &held{cancel: cancel, conf: key, stopped: make(chan struct{})}
			m.live[e.ID] = h
			go m.hold(hctx, e, h)
		}
		if h != nil {
			h.conf = key
		}
		switch {
		case e.Deleting:
			m.teardown(ctx, e, h)
		case e.InstallStatus == "pending":
			m.install(ctx, e, h)
		}
	}
	for id, h := range m.live {
		if !seen[id] {
			h.cancel()
			delete(m.live, id)
		}
	}
	return nil
}

func onlyPinned(a, b string) bool {
	return strings.HasSuffix(a, "|") && strings.HasPrefix(b, a)
}

// hold keeps a session to one exit open, reconnecting with backoff, until
// ctx ends.
func (m *Manager) hold(ctx context.Context, e store.SSHExitSession, h *held) {
	defer close(h.stopped)
	backoff := 5 * time.Second
	ep := Endpoint{Host: e.Host, Port: e.Port, User: e.Username, PrivateKey: e.PrivateKey}
	if e.HostKey != nil {
		ep.HostKey = *e.HostKey
	}
	// "connecting" once; while retrying, the last error stays visible.
	_ = m.st.SetSSHExitState(ctx, e.ID, "connecting", nil, nil)
	for ctx.Err() == nil {
		up := time.Now()
		err := m.session(ctx, e, &ep, h)
		if ctx.Err() != nil {
			return
		}
		msg := err.Error()
		_ = m.st.SetSSHExitState(ctx, e.ID, "error", &msg, nil)
		slog.Warn("SSH exit session ended", "exit", e.Name, "host", e.Host, "err", msg)
		if time.Since(up) > 2*time.Minute {
			backoff = 5 * time.Second // it was up a while: retry promptly
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// session runs one connection: dial, forward, keep alive. It returns why it
// ended.
func (m *Manager) session(ctx context.Context, e store.SSHExitSession, ep *Endpoint, h *held) error {
	client, err := Dial(ctx, *ep, func(fp string) error {
		slog.Info("pinning the SSH exit's host key on first contact", "exit", e.Name, "fingerprint", fp)
		if err := m.st.PinSSHExitHostKey(ctx, e.ID, fp); err != nil {
			return err
		}
		ep.HostKey = fp
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not connect to %s@%s:%d: %v", e.Username, e.Host, e.Port, err)
	}
	defer client.Close()

	stopGW, gwErr, err := Forward(client, e.RemotePort, m.cfg.Gateway)
	if err != nil {
		return err
	}
	defer stopGW()
	var storeErr <-chan error
	warn := ""
	if m.cfg.Store != "" {
		stop, errc, err := Forward(client, m.cfg.StorePort, m.cfg.Store)
		if err != nil {
			// The worker still works without it; only uploads (screenshots)
			// fail, and the reason is shown rather than the exit marked down.
			warn = "connected, but screenshots will not upload: " + err.Error()
		} else {
			defer stop()
			storeErr = errc
		}
	}

	remote, _, _ := net.SplitHostPort(client.RemoteAddr().String())
	h.mu.Lock()
	h.client, h.remote = client, remote
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.client = nil
		h.mu.Unlock()
	}()
	var lastErr *string
	if warn != "" {
		lastErr = &warn
	}
	_ = m.st.SetSSHExitState(ctx, e.ID, "connected", lastErr, &remote)
	slog.Info("SSH exit connected", "exit", e.Name, "host", e.Host, "remote_port", e.RemotePort)

	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	go KeepAlive(kctx, client, m.cfg.KeepAlive)
	wait := make(chan error, 1)
	go func() { wait <- client.Wait() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-gwErr:
		return fmt.Errorf("the tunnel to the gateway closed: %v", err)
	case err := <-storeErr:
		return fmt.Errorf("the tunnel to the object store closed: %v", err)
	case err := <-wait:
		if err == nil {
			return fmt.Errorf("the VPS closed the session")
		}
		return fmt.Errorf("the session dropped: %v", err)
	}
}

// connected returns the live client and the address it reached, or nil.
func (h *held) connected() (*ssh.Client, string) {
	if h == nil {
		return nil, ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.client, h.remote
}

func (h *held) claim() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.busy {
		return false
	}
	h.busy = true
	return true
}

func (h *held) release() {
	h.mu.Lock()
	h.busy = false
	h.mu.Unlock()
}

// install runs a pending install once the session is up. Called with m.mu
// held; the work itself runs in its own goroutine.
func (m *Manager) install(ctx context.Context, e store.SSHExitSession, h *held) {
	client, remote := h.connected()
	if client == nil || !h.claim() {
		return // not connected yet: the next pass tries again
	}
	go func() {
		defer h.release()
		ok, err := m.st.StartSSHExitInstall(ctx, e.ID)
		if err != nil || !ok {
			return
		}
		log, err := m.runInstall(ctx, client, e, remote)
		if err != nil {
			slog.Warn("worker install failed", "exit", e.Name, "err", err)
			_ = m.st.FinishSSHExitInstall(ctx, e.ID, false, err.Error()+"\n\n"+log)
			return
		}
		slog.Info("worker installed", "exit", e.Name, "worker", e.WorkerName)
		_ = m.st.FinishSSHExitInstall(ctx, e.ID, true, log)
	}()
}

func (m *Manager) runInstall(ctx context.Context, client *ssh.Client, e store.SSHExitSession, remote string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	var egress *string
	if net.ParseIP(remote) != nil {
		egress = &remote
	}
	// Single use, short-lived, and never stored: it exists in the database
	// only as a hash, and in the clear only inside this session.
	if err := m.st.CreatePreapprovedEnrollmentToken(ctx, sum[:], e.PoolID, 30*time.Minute, egress); err != nil {
		return "", fmt.Errorf("could not mint an enrolment token: %v", err)
	}
	script, err := Script(InstallSpec{
		Image: m.cfg.WorkerImage, Token: token, WorkerName: e.WorkerName,
		GatewayPort: e.RemotePort, StoreHost: m.cfg.StoreHost,
	})
	if err != nil {
		return "", err
	}
	out, err := Run(ctx, client, script, 15*time.Minute)
	out = strings.ReplaceAll(out, token, "[token]")
	if err != nil {
		return out, fmt.Errorf("%s", FailureReason(out))
	}
	return out, nil
}

// teardown removes the worker from the VPS when the session is up, then the
// exit. A VPS that is gone keeps nothing worth waiting for: the row goes.
func (m *Manager) teardown(ctx context.Context, e store.SSHExitSession, h *held) {
	client, _ := h.connected()
	if h != nil && !h.claim() {
		return
	}
	go func() {
		if h != nil {
			defer h.release()
		}
		if client != nil {
			if out, err := Run(ctx, client, UninstallScript(), 2*time.Minute); err != nil {
				slog.Warn("could not remove the worker from the VPS", "exit", e.Name, "err", err, "output", out)
			}
		}
		m.mu.Lock()
		if h := m.live[e.ID]; h != nil {
			h.cancel()
			delete(m.live, e.ID)
		}
		m.mu.Unlock()
		if err := m.st.DeleteSSHExit(ctx, e.ID); err != nil {
			slog.Warn("could not delete the SSH exit", "exit", e.Name, "err", err)
		}
		slog.Info("SSH exit removed", "exit", e.Name, "worker_removed", client != nil)
	}()
}
