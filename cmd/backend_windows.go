//go:build windows

package cmd

import "github.com/asnowfix/secret/backend"

func selectBackend() backend.Backend {
	return backend.NewCredentialManager()
}
