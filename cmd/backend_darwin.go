//go:build darwin

package cmd

import "github.com/asnowfix/secret/backend"

func selectBackend() backend.Backend {
	return backend.NewKeychain()
}
