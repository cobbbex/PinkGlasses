package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/benlik386/pinkglasses/internal/secret"
)

// SSHExit is a VPS the connector holds an SSH session to, carrying a worker
// for a control plane that is not reachable from the internet. The private
// key and any pending enrolment token are sealed and never part of the JSON.
type SSHExit struct {
	ID            uuid.UUID  `json:"id"`
	OwnerID       uuid.UUID  `json:"owner_id"`
	Name          string     `json:"name"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Username      string     `json:"username"`
	PublicKey     string     `json:"public_key"`
	HostKey       *string    `json:"host_key,omitempty"`
	RemotePort    int        `json:"remote_port"`
	PoolID        *uuid.UUID `json:"pool_id,omitempty"`
	WorkerName    string     `json:"worker_name"`
	Status        string     `json:"status"`
	LastError     *string    `json:"last_error,omitempty"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	RemoteAddr    *string    `json:"remote_addr,omitempty"`
	InstallStatus string     `json:"install_status"`
	InstallLog    *string    `json:"install_log,omitempty"`
	InstalledAt   *time.Time `json:"installed_at,omitempty"`
	Deleting      bool       `json:"deleting"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
}

const sshExitCols = `id, owner_id, name, host, port, username, public_key, host_key, remote_port,
	pool_id, worker_name, status, last_error, connected_at, remote_addr,
	install_status, install_log, installed_at, deleting, created_by, created_at`

func scanSSHExit(row interface{ Scan(...any) error }) (SSHExit, error) {
	var e SSHExit
	err := row.Scan(&e.ID, &e.OwnerID, &e.Name, &e.Host, &e.Port, &e.Username, &e.PublicKey,
		&e.HostKey, &e.RemotePort, &e.PoolID, &e.WorkerName, &e.Status, &e.LastError,
		&e.ConnectedAt, &e.RemoteAddr, &e.InstallStatus, &e.InstallLog, &e.InstalledAt,
		&e.Deleting, &e.CreatedBy, &e.CreatedAt)
	return e, err
}

// CreateSSHExit seals the private key and stores the exit. Sealing happens
// here so there is no path that writes one unsealed.
func (s *Store) CreateSSHExit(ctx context.Context, e SSHExit, privateKey []byte) (SSHExit, error) {
	sealed, err := secret.Seal(privateKey)
	if err != nil {
		return SSHExit{}, err
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO ssh_exit (owner_id, name, host, port, username, private_key, public_key,
		                      remote_port, pool_id, worker_name, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+sshExitCols,
		e.OwnerID, e.Name, e.Host, e.Port, e.Username, sealed, e.PublicKey,
		e.RemotePort, e.PoolID, e.WorkerName, e.CreatedBy)
	return scanSSHExit(row)
}

// ListSSHExits returns one account's exits, or every exit when owner is nil
// (an administrator's view).
func (s *Store) ListSSHExits(ctx context.Context, owner *uuid.UUID) ([]SSHExit, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+sshExitCols+` FROM ssh_exit
		WHERE $1::uuid IS NULL OR owner_id=$1 ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SSHExit{}
	for rows.Next() {
		e, err := scanSSHExit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetSSHExit returns one exit if owner may see it (nil owner: anyone's).
func (s *Store) GetSSHExit(ctx context.Context, id uuid.UUID, owner *uuid.UUID) (SSHExit, bool, error) {
	e, err := scanSSHExit(s.Pool.QueryRow(ctx, `SELECT `+sshExitCols+` FROM ssh_exit
		WHERE id=$1 AND ($2::uuid IS NULL OR owner_id=$2)`, id, owner))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SSHExit{}, false, nil
		}
		return SSHExit{}, false, err
	}
	return e, true, nil
}

// RequestSSHExitInstall asks the connector to install the worker. It refuses
// while an install is already under way.
func (s *Store) RequestSSHExitInstall(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE ssh_exit SET install_status='pending', install_log=NULL
		WHERE id=$1 AND NOT deleting AND install_status NOT IN ('pending','running')`, id)
	return tag.RowsAffected() == 1, err
}

// MarkSSHExitDeleting hands the exit to the connector to tear down: it
// removes the worker from the VPS if it can still reach it, then the row.
func (s *Store) MarkSSHExitDeleting(ctx context.Context, id uuid.UUID, owner *uuid.UUID) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE ssh_exit SET deleting=true
		WHERE id=$1 AND ($2::uuid IS NULL OR owner_id=$2)`, id, owner)
	return tag.RowsAffected() == 1, err
}

// --- the connector's side ---

// SSHExitSession is what the connector needs to hold one session: the exit
// and its private key in the clear.
type SSHExitSession struct {
	SSHExit
	PrivateKey []byte
}

// SSHExitSessions returns every exit with its key opened. Only the connector
// calls this, and the key never leaves its process.
func (s *Store) SSHExitSessions(ctx context.Context) ([]SSHExitSession, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+sshExitCols+`, private_key FROM ssh_exit`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHExitSession
	for rows.Next() {
		var x SSHExitSession
		var key []byte
		e := &x.SSHExit
		if err := rows.Scan(&e.ID, &e.OwnerID, &e.Name, &e.Host, &e.Port, &e.Username, &e.PublicKey,
			&e.HostKey, &e.RemotePort, &e.PoolID, &e.WorkerName, &e.Status, &e.LastError,
			&e.ConnectedAt, &e.RemoteAddr, &e.InstallStatus, &e.InstallLog, &e.InstalledAt,
			&e.Deleting, &e.CreatedBy, &e.CreatedAt, &key); err != nil {
			return nil, err
		}
		if x.PrivateKey, err = secret.Open(key); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// SetSSHExitState records the session's state as the connector sees it.
func (s *Store) SetSSHExitState(ctx context.Context, id uuid.UUID, status string, lastErr, remoteAddr *string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE ssh_exit SET status=$2, last_error=$3,
		  remote_addr = COALESCE($4, remote_addr),
		  connected_at = CASE WHEN $2='connected' AND status<>'connected' THEN now()
		                      WHEN $2='connected' THEN connected_at ELSE NULL END
		WHERE id=$1`, id, status, lastErr, remoteAddr)
	return err
}

// PinSSHExitHostKey records the host key seen on first contact. It only
// writes when none is pinned yet, so a later key can never replace it.
func (s *Store) PinSSHExitHostKey(ctx context.Context, id uuid.UUID, fingerprint string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE ssh_exit SET host_key=$2 WHERE id=$1 AND host_key IS NULL`, id, fingerprint)
	return err
}

// StartSSHExitInstall claims a pending install, so it is attempted once
// whatever happens next.
func (s *Store) StartSSHExitInstall(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE ssh_exit SET install_status='running'
		WHERE id=$1 AND install_status='pending'`, id)
	return tag.RowsAffected() == 1, err
}

// FinishSSHExitInstall records how an install ended and what it printed.
func (s *Store) FinishSSHExitInstall(ctx context.Context, id uuid.UUID, ok bool, log string) error {
	status := "failed"
	if ok {
		status = "done"
	}
	_, err := s.Pool.Exec(ctx, `UPDATE ssh_exit SET install_status=$2, install_log=$3,
		installed_at = CASE WHEN $2='done' THEN now() ELSE installed_at END WHERE id=$1`, id, status, log)
	return err
}

// DeleteSSHExit removes the row once the connector has torn the exit down.
func (s *Store) DeleteSSHExit(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM ssh_exit WHERE id=$1`, id)
	return err
}

// CreatePreapprovedEnrollmentToken mints a single-use token whose worker is
// active on arrival and whose egress is recorded as the given address — for
// a token delivered over an SSH session the app itself authenticated.
func (s *Store) CreatePreapprovedEnrollmentToken(ctx context.Context, hash []byte, poolID *uuid.UUID, ttl time.Duration, egress *string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO enrollment_token (token_hash, pool_id, expires_at, max_uses, kind, preapproved, egress_hint)
		VALUES ($1,$2, now()+$3::interval, 1, 'vps', true, $4::inet)`,
		hash, poolID, ttl.String(), egress)
	return err
}
