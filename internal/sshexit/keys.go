// Package sshexit carries a worker on a VPS for a control plane nothing on
// the internet can reach.
//
// The worker dials the gateway; a gateway at home, behind NAT, cannot be
// dialled. So the connection is made the other way round: the connector
// opens an SSH session to the VPS and asks its sshd to listen on the VPS's
// own loopback, handing each connection back down the session to the
// gateway. The worker on the VPS talks to http://127.0.0.1:<port> and never
// knows the difference; the gateway is never exposed, and the scan still
// leaves from the VPS's address.
//
//	home                                         VPS
//	gateway:8090 ◀── ssh -R 127.0.0.1:47090 ──── 127.0.0.1:47090 ◀── worker
//	minio:9000   ◀──        127.0.0.1:9000  ──── 127.0.0.1:9000  ◀── (uploads)
//
// The same session installs the worker, so nobody runs anything by hand.
package sshexit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GenerateKey makes an Ed25519 key pair for one exit: the private key in
// OpenSSH PEM form, to be sealed, and the authorized_keys line the user adds
// on the VPS.
func GenerateKey(comment string) (privatePEM []byte, authorized string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	privatePEM = pem.EncodeToMemory(block)
	authorized, err = AuthorizedLine(privatePEM, comment)
	return privatePEM, authorized, err
}

// AuthorizedLine checks a private key the user supplied and returns the
// authorized_keys line for it. A key with a passphrase is refused: the
// connector reconnects unattended and has nobody to ask.
func AuthorizedLine(privatePEM []byte, comment string) (string, error) {
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return "", errors.New("the key has a passphrase; the connector reconnects on its own and cannot type one — use a key without one, or let the app generate a key")
		}
		return "", fmt.Errorf("not a private key the connector can use: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

// Every value below lands in a shell command on someone's server, so each is
// held to a shape that cannot carry anything else.
var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	userRe  = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`) // a name, IPv4 or IPv6 literal
	imageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,200}(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// ValidName reports whether s can be a worker name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidUser reports whether s can be an SSH user name.
func ValidUser(s string) bool { return userRe.MatchString(s) }

// ValidHost reports whether s can be the address of the VPS.
func ValidHost(s string) bool {
	return hostRe.MatchString(s) && !strings.HasPrefix(s, "-")
}
