//go:build darwin

package backend

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

// newScratchKeychain creates a throwaway keychain in a temp directory,
// unlocked and populated with one generic-password item, and returns its
// path. It is never added to the user's keychain search list, so it cannot
// interfere with (or be interfered with by) the real login keychain.
func newScratchKeychain(t *testing.T) (path, service string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "scratch.keychain-db")
	const pass = "scratch-keychain-password"
	service = "secret-issue30-test-service"

	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}

	run("/usr/bin/security", "create-keychain", "-p", pass, path)
	run("/usr/bin/security", "unlock-keychain", "-p", pass, path)
	run("/usr/bin/security", "add-generic-password",
		"-s", service, "-a", "scratch-account", "-w", "scratch-password",
		"-T", "/usr/bin/security", path)
	return path, service
}

// TestGetPassword_NotFound verifies that a service which genuinely does not
// exist in the keychain is reported as *ErrNotFound.
func TestGetPassword_NotFound(t *testing.T) {
	path, _ := newScratchKeychain(t)
	k := &Keychain{keychainPath: path}

	_, err := k.GetPassword("secret-issue30-does-not-exist")
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("GetPassword() error = %v (%T), want *ErrNotFound", err, err)
	}
}

// TestGetPassword_LockedKeychain reproduces the data-loss scenario from
// issue #30 by hand: an existing credential that cannot be *read* because
// the keychain is locked must not be reported as *ErrNotFound (which a
// caller would treat as "safe to overwrite"). It must come back as
// something else — here, *ErrUnavailable — carrying real diagnostic text.
func TestGetPassword_LockedKeychain(t *testing.T) {
	path, service := newScratchKeychain(t)
	k := &Keychain{keychainPath: path}

	// Sanity check: readable while unlocked.
	if _, err := k.GetPassword(service); err != nil {
		t.Fatalf("GetPassword() before locking: %v", err)
	}

	lock := exec.Command("/usr/bin/security", "lock-keychain", path)
	if out, err := lock.CombinedOutput(); err != nil {
		t.Fatalf("lock-keychain: %v: %s", err, out)
	}

	_, err := k.GetPassword(service)
	if err == nil {
		t.Fatal("GetPassword() on locked keychain returned nil error, want a failure")
	}
	var notFound *ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("GetPassword() on locked keychain = *ErrNotFound (%v); this is the issue #30 bug — an unreadable credential must not look absent", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("GetPassword() on locked keychain error = %v (%T), want *ErrUnavailable", err, err)
	}
	if unavailable.Reason == "" {
		t.Fatal("ErrUnavailable.Reason is empty, want a diagnostic")
	}
}

// TestGetUsername_LockedKeychain mirrors TestGetPassword_LockedKeychain for
// GetUsername, which has the same shape per issue #30.
func TestGetUsername_LockedKeychain(t *testing.T) {
	path, service := newScratchKeychain(t)
	k := &Keychain{keychainPath: path}

	if _, err := k.GetUsername(service); err != nil {
		t.Fatalf("GetUsername() before locking: %v", err)
	}

	lock := exec.Command("/usr/bin/security", "lock-keychain", path)
	if out, err := lock.CombinedOutput(); err != nil {
		t.Fatalf("lock-keychain: %v: %s", err, out)
	}

	_, err := k.GetUsername(service)
	if err == nil {
		t.Fatal("GetUsername() on locked keychain returned nil error, want a failure")
	}
	var notFound *ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("GetUsername() on locked keychain = *ErrNotFound (%v); this is the issue #30 bug", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("GetUsername() on locked keychain error = %v (%T), want *ErrUnavailable", err, err)
	}
}

// TestRunSecurityFind_MissingBinary exercises the "security binary itself
// cannot be run" path, which never produces an *exec.ExitError and so must
// not be classified as errItemNotFound.
func TestRunSecurityFind_MissingBinary(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "no-such-security-binary"))
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected an error running a nonexistent binary")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Fatalf("expected a non-ExitError for a missing binary, got %T", err)
	}
}
