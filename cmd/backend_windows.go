//go:build windows

package cmd

import (
	"fmt"
	"os"

	"github.com/asnowfix/secret/backend"
)

// TODO: Implement Windows Credential Manager backend (Windows only).

func selectBackend() backend.Backend {
	fmt.Fprintln(os.Stderr, "*** no backend available for windows yet")
	os.Exit(1)
	return nil
}

var _ backend.Backend // ensure import is used
