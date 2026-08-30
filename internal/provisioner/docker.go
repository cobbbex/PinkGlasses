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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// managedLabel marks containers this service owns. Anything without it is
// invisible to the provisioner and can never be started, stopped or removed.
const (
	managedLabel = "asm.managed"
	roleLabel    = "asm.role"
	roleWorker   = "worker"
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

// Container is a managed worker container.
type Container struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
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

	body := map[string]any{
		"Image": sp.Image,
		"Env":   env,
		"Labels": map[string]string{
			managedLabel: "true",
			roleLabel:    roleWorker,
		},
		"HostConfig": map[string]any{
			// NET_RAW enables naabu's SYN scan; the worker falls back to a
			// connect scan without it, so this is an optimisation, not a need.
			"CapAdd":        []string{"NET_RAW"},
			"NetworkMode":   sp.Network,
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
		},
	}

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
