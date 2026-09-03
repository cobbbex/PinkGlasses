package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/benlik386/pinkglasses/internal/secret"
)

// VPNConfig is a tunnel a scan can leave through. The config body is sealed and
// is never part of this struct as JSON — only the server ever sees it, and only
// when handing it to a worker that is about to use it.
type VPNConfig struct {
	ID            uuid.UUID  `json:"id"`
	ScopeID       uuid.UUID  `json:"scope_id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"` // wireguard | openvpn
	Endpoint      *string    `json:"endpoint,omitempty"`
	LastEgressIP  *string    `json:"last_egress_ip,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
}

const vpnCols = `id, scope_id, name, kind, endpoint, last_egress_ip, last_checked_at, created_by, created_at`

func scanVPN(row interface{ Scan(...any) error }) (VPNConfig, error) {
	var v VPNConfig
	err := row.Scan(&v.ID, &v.ScopeID, &v.Name, &v.Kind, &v.Endpoint,
		&v.LastEgressIP, &v.LastCheckedAt, &v.CreatedBy, &v.CreatedAt)
	return v, err
}

// CreateVPNConfig seals the config body and stores it. Sealing happens here so
// there is no path that writes one unsealed.
func (s *Store) CreateVPNConfig(ctx context.Context, v VPNConfig, body []byte) (VPNConfig, error) {
	sealed, err := secret.Seal(body)
	if err != nil {
		return VPNConfig{}, err
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO vpn_config (scope_id, name, kind, endpoint, config, created_by)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+vpnCols,
		v.ScopeID, v.Name, v.Kind, v.Endpoint, sealed, v.CreatedBy)
	return scanVPN(row)
}

// ListVPNConfigs returns a scope's tunnels, metadata only.
func (s *Store) ListVPNConfigs(ctx context.Context, scopeID uuid.UUID) ([]VPNConfig, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+vpnCols+` FROM vpn_config WHERE scope_id=$1 ORDER BY name`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VPNConfig{}
	for rows.Next() {
		v, err := scanVPN(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVPNConfig returns one tunnel's metadata.
func (s *Store) GetVPNConfig(ctx context.Context, id uuid.UUID) (VPNConfig, error) {
	return scanVPN(s.Pool.QueryRow(ctx, `SELECT `+vpnCols+` FROM vpn_config WHERE id=$1`, id))
}

// OpenVPNConfigBody decrypts a config for delivery to a worker. The only caller
// is the gateway, and only for a worker that holds a lease on a task of the run
// this config belongs to.
func (s *Store) OpenVPNConfigBody(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var sealed []byte
	if err := s.Pool.QueryRow(ctx, `SELECT config FROM vpn_config WHERE id=$1`, id).Scan(&sealed); err != nil {
		return nil, err
	}
	return secret.Open(sealed)
}

// DeleteVPNConfig removes a tunnel.
func (s *Store) DeleteVPNConfig(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM vpn_config WHERE id=$1`, id)
	return ct.RowsAffected() > 0, err
}

// RecordVPNEgress notes the address a tunnel was last seen exiting from, so the
// UI can show that it works and what it looks like from outside.
func (s *Store) RecordVPNEgress(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE vpn_config SET last_egress_ip=$2, last_checked_at=now() WHERE id=$1`, id, ip)
	return err
}

// SetRunVPN records which tunnel a run used.
func (s *Store) SetRunVPN(ctx context.Context, runID, vpnID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scan_run SET vpn_config_id=$2 WHERE id=$1`, runID, vpnID)
	return err
}

// RunVPNConfigID returns the tunnel a run is using, if any.
//
// The column is read as text and parsed rather than scanned straight into a
// pointer: a NULL uuid does not scan into **uuid.UUID, and the resulting error
// was being swallowed by the caller's "no tunnel" branch — so a run bound to a
// VPN planned its tasks as though it were not.
func (s *Store) RunVPNConfigID(ctx context.Context, runID uuid.UUID) (*uuid.UUID, error) {
	var raw string
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(vpn_config_id::text, '') FROM scan_run WHERE id=$1`, runID).Scan(&raw); err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &id, nil
}
