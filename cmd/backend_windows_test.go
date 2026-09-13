//go:build windows

package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

func TestSelectBackend_Windows_DefaultsToCredentialManager(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.CredentialManager); !ok {
		t.Fatalf("got %T, want *backend.CredentialManager", b)
	}
}

func TestSelectBackend_Windows_EnvSelectsCredentialManagerExplicitly(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "credential-manager")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.CredentialManager); !ok {
		t.Fatalf("got %T, want *backend.CredentialManager", b)
	}
}

func TestSelectBackend_Windows_UnrecognisedEnvValueErrors(t *testing.T) {
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

// TestSelectBackend_Windows_AllOwnNamesAccepted is the intra-platform
// consistency check for "must fix 1" in the PR #63 review — see the darwin
// equivalent (TestSelectBackend_Darwin_AllOwnNamesAccepted) for the full
// rationale, which applies identically here: windowsBackendNames and
// selectBackend()'s switch cases are hand-written lists in the same file
// that must agree, and this catches a name the slice claims is valid on
// windows but that the switch actually rejects.
func TestSelectBackend_Windows_AllOwnNamesAccepted(t *testing.T) {
	for _, name := range windowsBackendNames {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SECRET_BACKEND", name)

			if _, err := selectBackend(); err != nil {
				t.Fatalf("selectBackend() rejected %q, which windowsBackendNames claims is valid on windows: %v", name, err)
			}
		})
	}
}

// TestSelectBackend_Windows_UnrecognisedEnvValueNamesThisPlatform mirrors
// TestSelectBackend_Darwin_UnrecognisedEnvValueNamesThisPlatform: it asserts
// selectBackend() threads this file's own windowsBackendNames (not some
// other platform's names slice) into errUnrecognisedBackend. A plain typo is
// used because the ", not <goos>" half of the message only appears on the
// "valid elsewhere" branch — see
// TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform below for that.
func TestSelectBackend_Windows_UnrecognisedEnvValueNamesThisPlatform(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "typo")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, strings.Join(windowsBackendNames, ", ")) {
		t.Errorf("error %q does not list windowsBackendNames verbatim — selectBackend() may be threading the wrong names slice into errUnrecognisedBackend", msg)
	}
}

// TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform documents that
// a value which is a real backend name, just not one Windows accepts,
// still gets a hard error here — see issue #7's design question 1 — while
// the message distinguishes it from a plain typo (design question 2). It
// also covers the ", not <goos>" half of the message, comparing against
// runtime.GOOS (not a hardcoded "windows" string) so a call site that
// accidentally hardcodes the wrong GOOS literal fails this test when it
// runs on windows, which is the only platform this file builds on.
func TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform(t *testing.T) {
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
