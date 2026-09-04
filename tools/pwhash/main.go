// Command pwhash prints an argon2id hash for a password, for the rare case
// where one has to be written straight into the database — a locked-out install,
// or bringing an existing account to the seeded default.
package main

import (
	"fmt"
	"os"

	"github.com/benlik386/pinkglasses/internal/auth"
)

func main() {
	pw := auth.DefaultPassword
	if len(os.Args) > 1 {
		pw = os.Args[1]
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(h)
}
