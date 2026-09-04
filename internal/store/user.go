package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/benlik386/pinkglasses/internal/auth"
)

// User is an account that can sign in. The password hash is never part of the
// JSON: it does not leave this package except to be verified.
type User struct {
	ID          uuid.UUID  `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        auth.Role  `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// HasPassword says whether this account can sign in with a password at all.
	HasPassword bool `json:"has_password"`
}

// ErrUsernameTaken is returned when a username is already in use.
var ErrUsernameTaken = errors.New("that username is already taken")

const userCols = `id, username, display_name, role, disabled, created_at, last_login_at, password_hash IS NOT NULL`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.Disabled,
		&u.CreatedAt, &u.LastLoginAt, &u.HasPassword)
	return u, err
}

// CountUsers reports how many accounts exist. Zero is what puts the API into
// first-run mode.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n)
	return n, err
}

// CreateUser adds an account. An empty password means the account cannot sign
// in with one, which is how a proxy-authenticated user is represented.
//
// firstOnly makes the insert conditional on the table still being empty, so two
// concurrent requests cannot both create the first administrator.
func (s *Store) CreateUser(ctx context.Context, username, display, password string, role auth.Role, createdBy *uuid.UUID, firstOnly bool) (User, error) {
	var hash *string
	if password != "" {
		h, err := auth.HashPassword(password)
		if err != nil {
			return User{}, err
		}
		hash = &h
	}
	q := `INSERT INTO app_user (username, display_name, password_hash, role, created_by)
	      VALUES ($1,$2,$3,$4,$5)`
	if firstOnly {
		// The race that matters: without this, two requests arriving together
		// on a fresh install would each see zero users and each create an admin.
		q = `INSERT INTO app_user (username, display_name, password_hash, role, created_by)
		     SELECT $1,$2,$3,$4,$5 WHERE NOT EXISTS (SELECT 1 FROM app_user)`
	}
	q += ` RETURNING ` + userCols

	u, err := scanUser(s.Pool.QueryRow(ctx, q, username, display, hash, string(role), createdBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, errors.New("an account already exists; ask an administrator to add you")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return User{}, ErrUsernameTaken
	}
	return u, err
}

// UserByUsername looks an account up for sign-in, returning its hash separately
// so the hash never travels inside a struct that gets serialised.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, string, error) {
	var u User
	var hash *string
	err := s.Pool.QueryRow(ctx, `
		SELECT `+userCols+`, password_hash FROM app_user WHERE lower(username)=lower($1)`,
		username).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.Disabled,
		&u.CreatedAt, &u.LastLoginAt, &u.HasPassword, &hash)
	if err != nil {
		return User{}, "", err
	}
	if hash == nil {
		return u, "", nil
	}
	return u, *hash, nil
}

// GetUser returns one account.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id=$1`, id))
}

// ListUsers returns every account, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userCols+` FROM app_user ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser changes an account's username, display name, role or disabled flag.
//
// Renaming is safe for history: audit records and scope ownership point at the
// user id, not the name, so what somebody did stays attached to them. The two
// things a rename does move are what future `created_by` strings say, and which
// account a trusted proxy's X-Forwarded-User resolves to — so a rename has to be
// mirrored in the proxy if one is in front (architecture.md §10.2).
func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, username, display *string, role *auth.Role, disabled *bool) (User, error) {
	var roleStr *string
	if role != nil {
		v := string(*role)
		roleStr = &v
	}
	u, err := scanUser(s.Pool.QueryRow(ctx, `
		UPDATE app_user SET
		  username     = COALESCE($2, username),
		  display_name = COALESCE($3, display_name),
		  role         = COALESCE($4, role),
		  disabled     = COALESCE($5, disabled)
		WHERE id=$1 RETURNING `+userCols, id, username, display, roleStr, disabled))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, err
	}
	// A disabled user must stop being able to act now, not when their cookie
	// expires. Same for a demotion: the session carries no role of its own, but
	// dropping it is the honest way to make a privilege change take effect.
	if (disabled != nil && *disabled) || role != nil {
		_ = s.DeleteUserSessions(ctx, id)
	}
	return u, nil
}

// SetPassword replaces an account's password and drops its other sessions.
func (s *Store) SetPassword(ctx context.Context, id uuid.UUID, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE app_user SET password_hash=$2 WHERE id=$1`, id, hash)
	return err
}

// CountAdmins reports how many enabled administrators there are, so the last
// one cannot lock everybody out of the install.
func (s *Store) CountAdmins(ctx context.Context, excluding uuid.UUID) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM app_user WHERE role='admin' AND NOT disabled AND id <> $1`,
		excluding).Scan(&n)
	return n, err
}

// DeleteUser removes an account. Their sessions and tokens go with it; the rows
// they created keep the name they were created under.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `DELETE FROM app_user WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id uuid.UUID) {
	_, _ = s.Pool.Exec(ctx, `UPDATE app_user SET last_login_at=now() WHERE id=$1`, id)
}
