//go:build linux

package cmd

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

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

// The SECRET_BACKEND tests below call selectBackend() directly, which is
// only safe when isWSL() is false: on an actual WSL host it would exec
// into secret.exe (or os.Exit(1) if that isn't on PATH) and take the test
// process down with it. WSL_DISTRO_NAME is cleared so the test is
// deterministic regardless of ambient environment, then isWSL() is
// consulted for the remaining /proc/version-based check exactly as
// TestIsWSL_NoEnvVarFallsBackToProcVersion above does.
func skipOnWSL(t *testing.T) {
	t.Helper()
	t.Setenv("WSL_DISTRO_NAME", "")
	if isWSL() {
		t.Skip("running on an actual WSL host; selectBackend() would trampoline and exec/exit")
	}
}

func TestSelectBackend_Linux_DefaultsToSecretService(t *testing.T) {
	skipOnWSL(t)
	t.Setenv("SECRET_BACKEND", "")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.SecretService); !ok {
		t.Fatalf("got %T, want *backend.SecretService", b)
	}
}

func TestSelectBackend_Linux_EnvSelectsSecretServiceExplicitly(t *testing.T) {
	skipOnWSL(t)
	t.Setenv("SECRET_BACKEND", "secret-service")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.SecretService); !ok {
		t.Fatalf("got %T, want *backend.SecretService", b)
	}
}

func TestSelectBackend_Linux_UnrecognisedEnvValueErrors(t *testing.T) {
	skipOnWSL(t)
	t.Setenv("SECRET_BACKEND", "typo")

	b, err := selectBackend()
	if err == nil {
		t.Fatalf("expected an error, got backend %T", b)
	}
	if b != nil {
		t.Fatalf("expected a nil backend alongside the error, got %T", b)
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error %q does not name the offending value", err.Error())
	}
}

// TestSelectBackend_Linux_AllOwnNamesAccepted is the intra-platform
// consistency check for "must fix 1" in the PR #63 review — see the darwin
// equivalent (TestSelectBackend_Darwin_AllOwnNamesAccepted) for the full
// rationale, which applies identically here: linuxBackendNames and
// selectBackend()'s switch cases are hand-written lists in the same file
// that must agree, and this catches a name the slice claims is valid on
// linux but that the switch actually rejects.
func TestSelectBackend_Linux_AllOwnNamesAccepted(t *testing.T) {
	for _, name := range linuxBackendNames {
		t.Run(name, func(t *testing.T) {
			skipOnWSL(t)
			t.Setenv("SECRET_BACKEND", name)

			if _, err := selectBackend(); err != nil {
				t.Fatalf("selectBackend() rejected %q, which linuxBackendNames claims is valid on linux: %v", name, err)
			}
		})
	}
}

// TestSelectBackend_Linux_UnrecognisedEnvValueNamesThisPlatform mirrors
// TestSelectBackend_Darwin_UnrecognisedEnvValueNamesThisPlatform: it asserts
// selectBackend() threads this file's own linuxBackendNames (not some other
// platform's names slice) into errUnrecognisedBackend. A plain typo is used
// because the ", not <goos>" half of the message only appears on the "valid
// elsewhere" branch — see
// TestSelectBackend_Linux_ValueValidOnlyOnAnotherPlatform below for that.
func TestSelectBackend_Linux_UnrecognisedEnvValueNamesThisPlatform(t *testing.T) {
	skipOnWSL(t)
	t.Setenv("SECRET_BACKEND", "typo")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, strings.Join(linuxBackendNames, ", ")) {
		t.Errorf("error %q does not list linuxBackendNames verbatim — selectBackend() may be threading the wrong names slice into errUnrecognisedBackend", msg)
	}
}

// TestSelectBackend_Linux_ValueValidOnlyOnAnotherPlatform mirrors
// TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform, which was the
// only platform with this end-to-end case before the PR #63 review pointed
// out darwin and linux lacked it. It also covers the ", not <goos>" half of
// the message, comparing against runtime.GOOS (not a hardcoded "linux"
// string) so a call site that accidentally hardcodes the wrong GOOS literal
// fails this test when it runs on linux, which is the only platform this
// file builds on.
func TestSelectBackend_Linux_ValueValidOnlyOnAnotherPlatform(t *testing.T) {
	skipOnWSL(t)
	t.Setenv("SECRET_BACKEND", "keychain")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "only available on darwin") {
		t.Errorf("error %q does not explain that this name is valid on a different platform", msg)
	}
	if !strings.Contains(msg, ", not "+runtime.GOOS) {
		t.Errorf("error %q does not say \", not %s\" — selectBackend() may be passing the wrong GOOS literal to errUnrecognisedBackend", msg, runtime.GOOS)
	}
}

// trampolineTargetName is the other part of the WSL-trampoline decision
// that is safe to unit test without a real WSL+Windows round-trip: unlike
// trampolineToWindows (which syscall.Execs or os.Exit(1)s and so cannot run
// inside `go test`), it is a pure function of os.Args[0]. This is new
// coverage, not a pre-existing gap being left alone — before this file, the
// trampoline hardcoded "secret.exe" and had nothing binary-name-dependent
// to test.
func TestTrampolineTargetName(t *testing.T) {
	cases := []struct {
		name   string
		arg0   string
		wanted string
	}{
		{"plain secret binary", "/usr/local/bin/secret", "secret.exe"},
		{"secret invoked relative to cwd", "./secret", "secret.exe"},
		{"git-credential-secret, invoked by git under that exact name", "git-credential-secret", "git-credential-secret.exe"},
		{"git-credential-secret via absolute PATH lookup", "/home/user/go/bin/git-credential-secret", "git-credential-secret.exe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := os.Args
			t.Cleanup(func() { os.Args = old })
			os.Args = []string{c.arg0}

			if got := trampolineTargetName(); got != c.wanted {
				t.Fatalf("got %q, want %q", got, c.wanted)
			}
		})
	}
}
