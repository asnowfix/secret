//go:build darwin

package cmd

import "github.com/asnowfix/secret/backend"

var forceKeychain bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&forceKeychain, "keychain", "k", false,
		"force the Keychain backend (login.keychain-db via /usr/bin/security)")
}

func selectBackend() backend.Backend {
	if forceKeychain {
		return backend.NewKeychain()
	}
	pa := backend.NewPasswordsApp()
	if pa.IsAvailable() == nil {
		return pa
	}
	return backend.NewKeychain()
}
