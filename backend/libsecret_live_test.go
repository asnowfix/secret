//go:build linux

package backend

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestSecretServiceLive exercises NewSecretService against a real Secret
// Service provider over a real D-Bus session — the only thing that can
// actually prove this backend speaks the protocol correctly, since no
// Linux desktop is available to the maintainer for manual verification.
//
// It is skipped unless SECRET_LIVE_DBUS_TEST=1, because it needs a session
// D-Bus bus with a Secret Service provider registered on it (typically
// gnome-keyring-daemon --components=secrets, already unlocked). Plain
// `go test ./...` — on a developer machine or in the default CI job — must
// stay green without any of that set up, so this test opts in rather than
// opts out.
//
// See .github/workflows/ci.yml for the dbus-run-session + gnome-keyring
// recipe that sets SECRET_LIVE_DBUS_TEST=1 in CI, and the PR description
// for how this was also verified locally in a throwaway container before
// being wired into CI.
func TestSecretServiceLive(t *testing.T) {
	if os.Getenv("SECRET_LIVE_DBUS_TEST") != "1" {
		t.Skip("set SECRET_LIVE_DBUS_TEST=1 to run this test against a real Secret Service provider (see .github/workflows/ci.yml)")
	}

	s := NewSecretService()
	if err := s.IsAvailable(); err != nil {
		t.Fatalf("IsAvailable: %v (is a Secret Service provider running and unlocked?)", err)
	}

	service := fmt.Sprintf("secret-cli-live-test-%d", os.Getpid())
	account := "alice"
	password := "hunter2-live-test"

	t.Cleanup(func() {
		_ = s.Delete(service) // best-effort; a failing test may have already deleted it
	})

	if _, err := s.GetPassword(service); err == nil {
		t.Fatalf("expected no pre-existing credential for %q", service)
	}

	if err := s.Add(service, account, password); err != nil {
		t.Fatalf("Add: %v", err)
	}

	gotUser, err := s.GetUsername(service)
	if err != nil {
		t.Fatalf("GetUsername: %v", err)
	}
	if gotUser != account {
		t.Fatalf("GetUsername = %q, want %q", gotUser, account)
	}

	gotPass, err := s.GetPassword(service)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if gotPass != password {
		t.Fatalf("GetPassword = %q, want %q", gotPass, password)
	}

	names, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, n := range names {
		if n == service {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("List() = %v, expected it to contain %q", names, service)
	}

	if err := s.Delete(service); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.GetPassword(service)
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ErrNotFound after Delete, got %v (%T)", err, err)
	}
}
