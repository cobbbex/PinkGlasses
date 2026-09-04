// Package provisioner manages local worker containers on behalf of the UI.
//
// SECURITY: this is the ONLY component that touches the Docker socket, and it
// is deliberately a separate binary and container. The socket is root-equivalent
// on the host, so it must not live in the api — which is internet-adjacent and
// holds a complete map of your attack surface. This service speaks a tiny fixed
// vocabulary (list / scale local workers) and cannot run arbitrary Docker
// commands, so a bug in the API cannot become host root.
package provisioner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// managedLabel marks containers this service owns. Anything without it is
// invisible to the provisioner and can never be started, stopped or removed.
const (
	managedLabel = "asm.managed"
	roleLabel    = "asm.role"
	roleWorker   = "worker"
	// roleVPNGateway holds a tunnel and nothing else. The run's workers join
	// its network namespace, so they scan from its address without holding any
	// network privilege of their own.
	roleVPNGateway = "vpn-gateway"
	// runLabel ties a container to the run that asked for it, so teardown can
	// find every container of a fleet and a restart can find orphans.
	runLabel = "asm.run"
)

// Docker is a minimal Docker Engine API client over the unix socket. It uses
// the stdlib only — no SDK — both to keep dependencies small and to keep the
// surface we expose to the socket deliberately narrow. Podman's Docker-compatible
// socket works too.
type Docker struct {
	http *http.Client
}

// NewDocker builds a client bound to a unix socket path.
func NewDocker(socket string) *Docker {
	return &Docker{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Container is a managed container.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

// Role returns what a managed container is for.
func (c Container) Role() string { return c.Labels[roleLabel] }

// RunID returns the run a container belongs to, or "" for a standing worker.
func (c Container) RunID() string { return c.Labels[runLabel] }

// Healthy reports whether Docker's healthcheck has passed. Only the VPN
// gateway defines one; anything else is considered ready once it is running.
func (c Container) Healthy() bool {
	return strings.Contains(c.Status, "healthy") && !strings.Contains(c.Status, "unhealthy")
}

func (d *Docker) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker socket: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("docker %s %s: %s: %s", method, path, resp.Status, buf.String())
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// List returns the worker containers this service manages.
func (d *Docker) List(ctx context.Context) ([]Container, error) {
	filters := url.QueryEscape(fmt.Sprintf(
		`{"label":["%s=true","%s=%s"]}`, managedLabel, roleLabel, roleWorker))
	var out []Container
	err := d.do(ctx, http.MethodGet, "/containers/json?all=true&filters="+filters, nil, &out)
	return out, err
}

// Spec describes the worker container to create.
type Spec struct {
	Image       string
	GatewayURL  string
	EnrollToken string
	Network     string
	NamePrefix  string
	Concurrency string
	// RunID, when set, labels the container as belonging to one run's fleet.
	RunID string
	// NetnsContainer, when set, makes this container share another's network
	// namespace instead of joining a network of its own. That is how a run's
	// workers inherit the VPN gateway's egress: same interfaces, same routes,
	// no privilege needed in the worker.
	NetnsContainer string
	// Role labels what the container is for.
	Role string
	// VPNKind and VPNConfig are the tunnel a gateway container carries.
	//
	// The configuration reaches the container through its environment, which
	// means anything able to read `docker inspect` can read it. That is already
	// root-equivalent access on this host — the provisioner holds the Docker
	// socket — so this widens no boundary, but it is worth knowing before
	// deciding where to run this.
	VPNKind   string
	VPNConfig string
}

// Create starts one new worker container.
func (d *Docker) Create(ctx context.Context, sp Spec, index int) (string, error) {
	name := fmt.Sprintf("%s-%d-%d", sp.NamePrefix, index, time.Now().UnixNano()%100000)

	env := []string{
		"ASM_GATEWAY_URL=" + sp.GatewayURL,
		"ASM_ENROLL_TOKEN=" + sp.EnrollToken,
	}
	if sp.Concurrency != "" {
		env = append(env, "ASM_WORKER_MAX_CONCURRENCY="+sp.Concurrency)
	}
	if sp.VPNKind != "" {
		env = append(env, "PG_VPN_KIND="+sp.VPNKind, "PG_VPN_CONFIG="+sp.VPNConfig)
	}

	role := sp.Role
	if role == "" {
		role = roleWorker
	}
	labels := map[string]string{managedLabel: "true", roleLabel: role}
	if sp.RunID != "" {
		labels[runLabel] = sp.RunID
	}

	network := sp.Network
	if sp.NetnsContainer != "" {
		// Sharing a namespace is exclusive: the container gets that one's
		// interfaces and routes, and no network of its own.
		network = "container:" + sp.NetnsContainer
		// Its egress is therefore not its own to change, and was verified by
		// the gateway before this container existed. The worker reads this so
		// that being handed a tunnel it cannot build is a logged no-op rather
		// than a failed task.
		env = append(env, "PG_EGRESS_FIXED=1")
	}

	host := map[string]any{
		// NET_RAW enables naabu's SYN scan; the worker falls back to a
		// connect scan without it, so this is an optimisation, not a need.
		"CapAdd":      []string{"NET_RAW"},
		"NetworkMode": network,
		// A fleet container must not outlive its run. Restarting one whose run
		// has finished would leave a worker enrolled into a pool nothing feeds.
		"RestartPolicy": map[string]any{"Name": "no"},
	}
	if sp.RunID == "" {
		host["RestartPolicy"] = map[string]any{"Name": "unless-stopped"}
	}

	body := map[string]any{
		"Image":  sp.Image,
		"Env":    env,
		"Labels": labels,
	}

	if role == roleVPNGateway {
		// The one container that needs network privilege: it builds the tunnel
		// every other container in the fleet then shares.
		host["CapAdd"] = []string{"NET_ADMIN", "NET_RAW"}
		host["Devices"] = []map[string]any{{
			"PathOnHost": "/dev/net/tun", "PathInContainer": "/dev/net/tun", "CgroupPermissions": "rwm",
		}}
		host["Sysctls"] = map[string]string{"net.ipv4.conf.all.src_valid_mark": "1"}
		body["Entrypoint"] = []string{"/usr/local/bin/vpngw"}
		// Healthy only once the tunnel is up and the address has changed, so
		// the workers are not started into a namespace that is not tunnelled.
		body["Healthcheck"] = map[string]any{
			"Test":        []string{"CMD", "/usr/local/bin/vpngw", "-check"},
			"Interval":    2_000_000_000,
			"Timeout":     3_000_000_000,
			"Retries":     40,
			"StartPeriod": 2_000_000_000,
		}
	}
	body["HostConfig"] = host

	var created struct {
		ID string `json:"Id"`
	}
	if err := d.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), body, &created); err != nil {
		return "", err
	}
	if err := d.do(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return created.ID, err
	}
	return created.ID, nil
}

// Remove stops and deletes a managed container. It refuses to touch anything
// that is not labelled as ours.
func (d *Docker) Remove(ctx context.Context, id string) error {
	managed, err := d.List(ctx)
	if err != nil {
		return err
	}
	ok := false
	for _, c := range managed {
		if c.ID == id {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("refusing to remove unmanaged container %s", id)
	}
	_ = d.do(ctx, http.MethodPost, "/containers/"+id+"/stop?t=10", nil, nil)
	return d.do(ctx, http.MethodDelete, "/containers/"+id+"?force=true", nil, nil)
}

// Inspected is the detail of one container that fleet building needs: whether
// its healthcheck has passed, and what it last said.
type Inspected struct {
	State    string
	Health   string
	EgressIP string
	LastLog  string
}

// Inspect reads a container's state and health.
func (d *Docker) Inspect(ctx context.Context, id string) (Inspected, error) {
	var raw struct {
		State struct {
			Status string `json:"Status"`
			Health *struct {
				Status string `json:"Status"`
				Log    []struct {
					Output string `json:"Output"`
				} `json:"Log"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := d.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &raw); err != nil {
		return Inspected{}, err
	}
	out := Inspected{State: raw.State.Status}
	if raw.State.Health != nil {
		out.Health = strings.ToLower(raw.State.Health.Status)
		if n := len(raw.State.Health.Log); n > 0 {
			last := strings.TrimSpace(raw.State.Health.Log[n-1].Output)
			out.LastLog = last
			// The healthcheck prints the address it is exiting from, so the
			// fleet can report the egress it actually got.
			if ip := strings.TrimSpace(strings.TrimPrefix(last, "egress=")); ip != last {
				out.EgressIP = ip
			}
		}
	}
	if out.LastLog == "" {
		out.LastLog = out.State
	}
	return out, nil
}

// Logs returns the last few lines a container printed.
//
// This exists for one message: when a VPN gateway exits before its tunnel comes
// up, the reason is openvpn's or wg's own complaint on stderr, and without it
// the operator is told only that a container "exited". The docker log stream is
// multiplexed with an 8-byte header per frame when the container has no TTY, so
// the frames are unwrapped rather than returned raw.
func (d *Docker) Logs(ctx context.Context, id string, tail int) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://docker/containers/%s/logs?stdout=1&stderr=1&tail=%d", id, tail), nil)
	if err != nil {
		return ""
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(demuxDockerLog(raw))
}

// demuxDockerLog strips the stream headers docker puts in front of each frame.
// A log that does not look framed is returned as it is, which is what a TTY
// container produces.
func demuxDockerLog(raw []byte) string {
	var b strings.Builder
	for i := 0; i+8 <= len(raw); {
		// A frame header is {stream, 0, 0, 0, len32be}; anything else means
		// this is not a framed stream.
		if raw[i] > 2 || raw[i+1] != 0 || raw[i+2] != 0 || raw[i+3] != 0 {
			return string(raw)
		}
		n := int(binary.BigEndian.Uint32(raw[i+4 : i+8]))
		i += 8
		if n < 0 || i+n > len(raw) {
			b.Write(raw[i:])
			break
		}
		b.Write(raw[i : i+n])
		i += n
	}
	return b.String()
}
