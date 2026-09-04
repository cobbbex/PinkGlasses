package auth

import "os"

// The credentials a fresh install starts with.
//
// Shipping a known username and password is a deliberate trade and worth being
// honest about: it is the pattern behind Mirai and a long line of breaches, and
// what this database holds — a complete map of somebody's external attack
// surface — is exactly what an attacker would want. It exists because getting
// started should not require reading the README, and because the alternative
// people actually reach for is worse.
//
// Three things make it defensible, and all three have to stay:
//
//  1. It is only ever created on an empty database, never restored if deleted.
//  2. The API logs it loudly at startup while it is still in use.
//  3. The UI carries a warning banner until the password is changed, and the
//     password is checked for real (`UsingDefaultPassword`) rather than
//     assumed from a flag that could drift.
//
// DefaultPassword is deliberately shorter than CheckPasswordPolicy allows, so
// it cannot be re-entered as a replacement for itself.
const (
	DefaultUsername = "admin"
	DefaultPassword = "pinkglasses"
)

// DefaultAdminPassword is the seed password, overridable so a deployment can
// start with something that was never published in a README.
//
//	ASM_DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 24)
//
// Setting it to "-" seeds no account at all, which puts the install back to
// asking for an administrator on first visit.
func DefaultAdminPassword() string {
	if v := os.Getenv("ASM_DEFAULT_ADMIN_PASSWORD"); v != "" {
		return v
	}
	return DefaultPassword
}

// SeedDisabled reports whether the operator has turned the default account off.
func SeedDisabled() bool { return os.Getenv("ASM_DEFAULT_ADMIN_PASSWORD") == "-" }
