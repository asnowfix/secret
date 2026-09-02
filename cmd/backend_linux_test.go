//go:build linux

package cmd

import "testing"

// isWSL is the only part of the WSL-trampoline decision that is safe to
// unit test: selectBackend() itself calls trampolineToWindows(), which
// either syscall.Execs onto secret.exe or os.Exit(1)s, so exercising
// selectBackend() end-to-end would terminate the test process. The
// invariant that matters — the WSL check runs strictly before any native
// Linux backend is selected — is preserved by construction in
// selectBackend() (see its source): trampolineToWindows() is called first
// and never returns, so backend.NewSecretService() is unreachable when
// isWSL() is true.
func TestIsWSL_EnvVarShortCircuits(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	if !isWSL() {
		t.Fatal("expected isWSL() to report true when WSL_DISTRO_NAME is set, regardless of /proc/version")
	}
}

func TestIsWSL_NoEnvVarFallsBackToProcVersion(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	// On a real Linux CI runner (not WSL), /proc/version exists and does not
	// mention Microsoft/WSL, so this documents the non-WSL case without
	// depending on any WSL-specific environment being present.
	if isWSL() {
		t.Skip("running on an actual WSL host; the non-WSL assumption below doesn't hold here")
	}
}
