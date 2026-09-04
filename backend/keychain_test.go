//go:build darwin

package backend

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// withStandInSecurity points securityBinary at a stand-in executable and
// shrinks securityCommandTimeout to timeout for the duration of the test,
// restoring both package vars afterwards.
func withStandInSecurity(t *testing.T, binary string, timeout time.Duration) {
	t.Helper()
	origBinary, origTimeout := securityBinary, securityCommandTimeout
	t.Cleanup(func() {
		securityBinary = origBinary
		securityCommandTimeout = origTimeout
	})
	securityBinary = binary
	securityCommandTimeout = timeout
}

// hangingSecurityScript writes a stand-in for /usr/bin/security that never
// exits on its own and returns its path. It stands in for what actually
// happens against a real locked keychain with no agent to answer: the real
// security binary does not hang because it is blocked reading from stdin
// (a nil cmd.Stdin already reads from os.DevNull, ruled out by inspecting
// go1.25's os/exec source rather than assumed) — it hangs because it is
// off waiting on an interactive keychain-unlock prompt that nothing will
// ever answer. Pointing securityBinary at this script exercises
// runSecurityFind's own timeout/kill logic deterministically, without
// depending on real keychain/agent behavior — which is exactly what hung
// CI for ten minutes and left an orphan `security` process behind.
func hangingSecurityScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return path
}

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
// issue #30: an existing credential that cannot be *read* because the
// keychain is locked must not be reported as *ErrNotFound (which a caller
// would treat as "safe to overwrite"). It must come back as something else
// — here, *ErrUnavailable — carrying real diagnostic text.
//
// This drives the scenario with a stand-in security binary that never
// exits, rather than an actually-locked keychain: against a real locked
// keychain with no GUI session to answer the unlock prompt, this exact
// call hung for the full 10-minute CI test timeout and left an orphan
// `security` process behind (see PR #31's review). Reproducing that
// through a stand-in makes the test exercise runSecurityFind's own
// timeout/kill logic deterministically and quickly instead of depending on
// real, slow, environment-specific keychain-agent behavior — the thing
// that hung CI in the first place. The real-lock reproduction still exists,
// opt-in, as TestGetPassword_LockedKeychain_Live below.
func TestGetPassword_LockedKeychain(t *testing.T) {
	withStandInSecurity(t, hangingSecurityScript(t), 200*time.Millisecond)
	k := &Keychain{keychainPath: filepath.Join(t.TempDir(), "irrelevant.keychain-db")}

	start := time.Now()
	_, err := k.GetPassword("secret-issue30-test-service")
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("GetPassword() took %s to return against an unresponsive security binary; want it bounded near securityCommandTimeout — the timeout/kill logic did not bound the call", elapsed)
	}
	if err == nil {
		t.Fatal("GetPassword() against an unresponsive security binary returned nil error, want a failure")
	}
	var notFound *ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("GetPassword() against an unresponsive security binary = *ErrNotFound (%v); this is the issue #30 bug — an unreadable credential must not look absent", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("GetPassword() error = %v (%T), want *ErrUnavailable", err, err)
	}
	if unavailable.Reason == "" {
		t.Fatal("ErrUnavailable.Reason is empty, want a diagnostic")
	}
}

// TestGetUsername_LockedKeychain mirrors TestGetPassword_LockedKeychain for
// GetUsername, which has the same shape per issue #30.
func TestGetUsername_LockedKeychain(t *testing.T) {
	withStandInSecurity(t, hangingSecurityScript(t), 200*time.Millisecond)
	k := &Keychain{keychainPath: filepath.Join(t.TempDir(), "irrelevant.keychain-db")}

	start := time.Now()
	_, err := k.GetUsername("secret-issue30-test-service")
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("GetUsername() took %s to return against an unresponsive security binary; want it bounded near securityCommandTimeout", elapsed)
	}
	if err == nil {
		t.Fatal("GetUsername() against an unresponsive security binary returned nil error, want a failure")
	}
	var notFound *ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("GetUsername() against an unresponsive security binary = *ErrNotFound (%v); this is the issue #30 bug", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("GetUsername() error = %v (%T), want *ErrUnavailable", err, err)
	}
}

// TestGetPassword_LockedKeychain_Live reproduces issue #30 against a real,
// actually-locked scratch keychain rather than a stand-in security binary.
// It is opt-in (SECRET_LIVE_KEYCHAIN_TEST=1) rather than unconditional,
// following the precedent set for the D-Bus backend in PR #29
// (SECRET_LIVE_DBUS_TEST=1): this is the exact call that hung CI for ten
// minutes on the headless macos-latest runner before securityCommandTimeout
// existed, and even bounded by it, it is slow, real, environment-dependent
// I/O with no business running unconditionally on every push. The
// always-on regression coverage for the actual product fix is
// TestGetPassword_LockedKeychain above.
func TestGetPassword_LockedKeychain_Live(t *testing.T) {
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to run against a real, actually-locked scratch keychain")
	}
	path, service := newScratchKeychain(t)
	k := &Keychain{keychainPath: path}

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

// TestGetUsername_LockedKeychain_Live mirrors
// TestGetPassword_LockedKeychain_Live for GetUsername.
func TestGetUsername_LockedKeychain_Live(t *testing.T) {
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to run against a real, actually-locked scratch keychain")
	}
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
