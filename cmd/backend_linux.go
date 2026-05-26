//go:build linux

package cmd

import (
	"fmt"
	"os"

	"github.com/asnowfix/secret/backend"
)

// TODO: Implement GNOME libsecret / Secret Service backend (Linux only).

func selectBackend() backend.Backend {
	fmt.Fprintln(os.Stderr, "*** no backend available for linux yet")
	os.Exit(1)
	return nil
}

var _ backend.Backend // ensure import is used
