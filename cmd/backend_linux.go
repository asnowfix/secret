//go:build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/asnowfix/secret/backend"
)

func selectBackend() backend.Backend {
	// trampolineToWindows never returns: it either syscall.Execs onto
	// secret.exe on the Windows host, or os.Exit(1)s. It must be tried
	// first and unconditionally win over any native Linux backend — WSL
	// users want the Windows host's credentials, not a WSL-local keyring,
	// even if a Secret Service daemon happens to be running inside WSL.
	if isWSL() {
		trampolineToWindows()
	}
	// Native Secret Service backend (GNOME Keyring, KWallet, ...).
	return backend.NewSecretService()
}

func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

func trampolineToWindows() {
	path, err := exec.LookPath("secret.exe")
	if err != nil {
		fmt.Fprintln(os.Stderr, "WSL detected but secret.exe not found in PATH.")
		fmt.Fprintln(os.Stderr, "Install secret for Windows via winget, scoop, or from the GitHub releases page.")
		os.Exit(1)
	}
	args := append([]string{"secret.exe"}, os.Args[1:]...)
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to exec secret.exe: %v\n", err)
		os.Exit(1)
	}
}
