//go:build darwin

package cmd

import "github.com/asnowfix/secret/backend"

func selectBackend() backend.Backend {
	pa := backend.NewPasswordsApp()
	if pa.IsAvailable() == nil {
		return pa
	}
	return backend.NewKeychain()
}
