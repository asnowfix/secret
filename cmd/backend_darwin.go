//go:build darwin

package cmd

import "github.com/asnowfix/secret/backend"

// TODO: Add Passwords.app backend (macOS only, no CLI yet — requires Security framework).

func selectBackend() backend.Backend {
	return backend.NewKeychain()
}
