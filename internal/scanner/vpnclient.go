package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// fetchVPNConfig asks the gateway for the config body of the tunnel this job
// requires. The body is never written to a log and lives only in the temporary
// directory the tunnel owns.
func (a *Agent) fetchVPNConfig(ctx context.Context, configID string) (kind, body string, err error) {
	url := fmt.Sprintf("%s/agent/v1/vpn-config?id=%s", a.cfg.GatewayURL, configID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Worker-Id", a.workerID)
	req.Header.Set("X-Worker-Credential", a.cred)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct{ Kind, Config string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", "", err
	}
	if out.Config == "" {
		return "", "", fmt.Errorf("the gateway returned an empty configuration")
	}
	return out.Kind, out.Config, nil
}
