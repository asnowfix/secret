//go:build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/asnowfix/secret/backend"
	"github.com/spf13/viper"
)

// linuxBackendNames lists the SECRET_BACKEND values accepted by the native
// (non-WSL) Linux path, in display order for errUnrecognisedBackend.
var linuxBackendNames = []string{"secret-service"}

func selectBackend() (backend.Backend, error) {
	// trampolineToWindows never returns: it either syscall.Execs onto this
	// process's Windows-native counterpart on the host (secret.exe or
	// git-credential-secret.exe, whichever this binary is — see
	// trampolineTargetName below), or os.Exit(1)s. It must be tried first
	// and unconditionally win over any native Linux backend — WSL users
	// want the Windows host's credentials, not a WSL-local keyring, even
	// if a Secret Service daemon happens to be running inside WSL. This is
	// also issue #7's design question 4: SECRET_BACKEND is deliberately
	// *not* consulted here to suppress the trampoline. syscall.Exec passes
	// os.Environ() through unchanged, so a SECRET_BACKEND set on the WSL
	// side already reaches secret.exe/git-credential-secret.exe on the
	// Windows host and is honoured there (see cmd/backend_windows.go) — the
	// conservative behaviour that needs no maintainer decision. Making the
	// variable suppress the trampoline instead would change a documented
	// invariant ("must ... unconditionally win over any native Linux
	// backend", above) and is out of scope for this change.
	if isWSL() {
		trampolineToWindows()
	}
	// Native Secret Service backend (GNOME Keyring, KWallet, ...). Only one
	// value is accepted today, but an unrecognised one is still a hard
	// error rather than a silent fall-back (issue #7's design question 1).
	switch name := viper.GetString("backend"); name {
	case "", "secret-service":
		return backend.NewSecretService(), nil
	default:
		return nil, errUnrecognisedBackend(name, "linux", linuxBackendNames)
	}
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

// trampolineTargetName picks the Windows-side binary to trampoline into,
// derived from os.Args[0]'s base name rather than hardcoded: this file's
// selectBackend() is shared by both the `secret` binary (see cmd/root.go)
// and the `git-credential-secret` binary (see cmd/gitcredential.go's
// RunGitCredentialHelper, called from cmd/git-credential-secret/main.go). A
// WSL-built `secret` re-exec must land on `secret.exe`; a WSL-built
// `git-credential-secret`, invoked by git under that exact name, must land
// on `git-credential-secret.exe` — running `secret.exe get` instead has no
// matching subcommand and fails. Both binaries are built for Windows and
// bundled together in every release archive (see .goreleaser.yaml's
// git-credential-secret-windows build and the shared archives block), so
// whichever name the WSL side was invoked as, its Windows-native
// counterpart should be sitting right next to it on PATH.
func trampolineTargetName() string {
	base := filepath.Base(os.Args[0])
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return base + ".exe"
}

func trampolineToWindows() {
	target := trampolineTargetName()
	path, err := exec.LookPath(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WSL detected but %s not found in PATH.\n", target)
		fmt.Fprintln(os.Stderr, "Install secret for Windows via winget, scoop, or from the GitHub releases page.")
		os.Exit(1)
	}
	args := append([]string{target}, os.Args[1:]...)
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to exec %s: %v\n", target, err)
		os.Exit(1)
	}
}
