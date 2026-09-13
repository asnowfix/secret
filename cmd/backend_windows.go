//go:build windows

package cmd

import (
	"github.com/asnowfix/secret/backend"
	"github.com/spf13/viper"
)

// windowsBackendNames lists the SECRET_BACKEND values accepted on Windows,
// in display order for errUnrecognisedBackend. There is only one backend
// today, but an unrecognised value is still a hard error rather than a
// silent fall-back (issue #7's design question 1) — this also matters for
// a value that arrives here via the WSL trampoline (cmd/backend_linux.go),
// since syscall.Exec passes the WSL side's environment through unchanged
// and a typo made on the Linux side should surface here rather than be
// swallowed.
var windowsBackendNames = []string{"credential-manager"}

func selectBackend() (backend.Backend, error) {
	switch name := viper.GetString("backend"); name {
	case "", "credential-manager":
		return backend.NewCredentialManager(), nil
	default:
		return nil, errUnrecognisedBackend(name, "windows", windowsBackendNames)
	}
}
