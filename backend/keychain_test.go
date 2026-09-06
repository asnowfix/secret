//go:build darwin

package backend

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseKeychainDumpServices(t *testing.T) {
	t.Parallel()
	// Trimmed sample of real `security dump-keychain` output: a generic
	// password entry (via the "svce" attribute) and an internet password
	// entry (via the "srvr" attribute), plus a duplicate to test dedup.
	dump := `keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="com.apple.assistant"
    "acct"<blob>="someone"
    "svce"<blob>="com.apple.assistant"
keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="someone@example.com"
    "srvr"<blob>="example.com"
keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "svce"<blob>="com.apple.assistant"
`

	got := parseKeychainDumpServices(dump)
	want := []string{"com.apple.assistant", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeychainDumpServices() = %v, want %v", got, want)
	}
}

func TestParseKeychainDumpServices_HexEncoded(t *testing.T) {
	t.Parallel()
	// "abc" hex-encoded, matching how dump-keychain renders non-ASCII values.
	dump := `class: "genp"
attributes:
    "svce"<blob>=0x616263  "abc"
`
	got := parseKeychainDumpServices(dump)
	want := []string{"abc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeychainDumpServices() = %v, want %v", got, want)
	}
}

func TestParseKeychainDumpServices_Empty(t *testing.T) {
	t.Parallel()
	got := parseKeychainDumpServices("")
	if len(got) != 0 {
		t.Errorf("parseKeychainDumpServices(\"\") = %v, want empty", got)
	}
}

// TestHexDecode_OddLength pins the length guard: the loop reads s in pairs
// and would index past the end without it. The input comes from parsing
// security's output, so a malformed value must be an error, not a panic.
func TestHexDecode_OddLength(t *testing.T) {
	t.Parallel()
	if _, err := hexDecode("616"); err == nil {
		t.Fatal("hexDecode(\"616\") = nil error, want a failure for an odd-length input")
	}
}

// ---------------------------------------------------------------------------
// Stand-in security binary
// ---------------------------------------------------------------------------

// standInTimeout is the timeout given to a Keychain driven by a responsive
// stand-in. It is generous relative to running a two-line shell script, and
// still bounds the test if the stand-in ever misbehaves.
const standInTimeout = 5 * time.Second

// hangTimeout is the timeout given to a Keychain driven by the stand-in that
// never exits. Assertions about elapsed time are made against this value, not
// against an unrelated constant, so shrinking it actually tightens the test.
const hangTimeout = 200 * time.Millisecond

// securityResponse is one canned reply from the stand-in security binary.
type securityResponse struct {
	stdout   string
	stderr   string
	exitCode int
}

// notFoundStderr is what /usr/bin/security actually prints for
// errSecItemNotFound. It is reproduced verbatim because runSecurity treats it
// as a not-found signal in its own right, independent of the exit code.
const notFoundStderr = `security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.`

// newStandInKeychain returns a *Keychain whose security CLI is a shell script
// answering each invocation from a canned response. Responses are keyed by
// subcommand, plus the read flag for the two find subcommands that take one:
// "find-generic-password -g", "find-generic-password -w",
// "delete-internet-password", "show-keychain-info", and so on. An invocation
// with no scripted response reports a definitive miss, exactly as the real
// binary does for a service that is simply not in the keychain.
//
// This is how the always-on tests in this file cover the macOS read path
// without a real keychain: the previous suite exercised failure paths only,
// so nothing in CI pinned which stream security's output arrives on, nor what
// GetUsername/GetPassword do with a successful lookup (issue #36, finding 1).
func newStandInKeychain(t *testing.T, timeout time.Duration, responses map[string]securityResponse) *Keychain {
	t.Helper()
	dir := t.TempDir()

	respDir := filepath.Join(dir, "responses")
	for key, resp := range responses {
		d := filepath.Join(respDir, strings.ReplaceAll(key, " ", "_"))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("create stand-in response dir: %v", err)
		}
		for name, content := range map[string]string{
			"out":  resp.stdout,
			"err":  resp.stderr,
			"exit": strconv.Itoa(resp.exitCode),
		} {
			if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
				t.Fatalf("write stand-in response %s/%s: %v", key, name, err)
			}
		}
	}

	script := "#!/bin/sh\n" +
		"key=\"$1\"\n" +
		"case \"$2\" in -g|-w) key=\"$1_$2\" ;; esac\n" +
		"d='" + respDir + "'/\"$key\"\n" +
		"if [ -d \"$d\" ]; then\n" +
		"\tcat \"$d/out\"\n" +
		"\tcat \"$d/err\" >&2\n" +
		"\texit \"$(cat \"$d/exit\")\"\n" +
		"fi\n" +
		"echo '" + notFoundStderr + "' >&2\n" +
		"exit " + strconv.Itoa(secItemNotFoundExitCode) + "\n"

	binary := filepath.Join(dir, "security")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath: filepath.Join(dir, "stand-in.keychain-db"),
		security:     binary,
		timeout:      timeout,
	}
}

// attributeDump is the attribute listing `security find-generic-password -g`
// prints for an existing item, trimmed to the lines this package parses.
func attributeDump(account string) string {
	return `keychain: "/Users/someone/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="` + account + `"
    "svce"<blob>="example-service"
`
}

// newHangingKeychain returns a *Keychain whose security CLI never exits. It
// stands in for what actually happens against a real locked keychain with no
// agent to answer: the real security binary does not hang because it is
// blocked reading stdin (a nil cmd.Stdin has read from os.DevNull since
// Go 1.0) — it hangs waiting on an interactive unlock prompt that nothing
// will ever answer. Driving that through a stand-in exercises runSecurity's
// own timeout/kill logic deterministically, without depending on real
// keychain/agent behavior — which is exactly what hung CI for ten minutes and
// left an orphan `security` process behind.
func newHangingKeychain(t *testing.T) *Keychain {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "security")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath: filepath.Join(dir, "irrelevant.keychain-db"),
		security:     binary,
		timeout:      hangTimeout,
	}
}

// newMissingBinaryKeychain returns a *Keychain pointed at a path where no
// executable exists, so that running it fails before any process starts.
func newMissingBinaryKeychain(t *testing.T) *Keychain {
	t.Helper()
	dir := t.TempDir()
	return &Keychain{
		keychainPath: filepath.Join(dir, "irrelevant.keychain-db"),
		security:     filepath.Join(dir, "no-such-security-binary"),
		timeout:      standInTimeout,
	}
}

// assertUnavailable asserts that err is *ErrUnavailable with a non-empty
// reason and, crucially, is not *ErrNotFound: reporting "could not read" as
// "not there" is the issue #30 bug this package's error classification exists
// to prevent, and cmd/set.go and cmd/gitcredential.go both act on the
// difference.
func assertUnavailable(t *testing.T, what string, err error) *ErrUnavailable {
	t.Helper()
	if err == nil {
		t.Fatalf("%s returned nil error, want a failure", what)
	}
	var notFound *ErrNotFound
	if errors.As(err, &notFound) {
		t.Fatalf("%s = *ErrNotFound (%v); an unreadable credential must not look absent", what, err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("%s error = %v (%T), want *ErrUnavailable", what, err, err)
	}
	if unavailable.Reason == "" {
		t.Fatalf("%s: ErrUnavailable.Reason is empty, want a diagnostic", what)
	}
	return unavailable
}

func assertNotFound(t *testing.T, what string, err error) {
	t.Helper()
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("%s error = %v (%T), want *ErrNotFound", what, err, err)
	}
}

// ---------------------------------------------------------------------------
// Read path: which stream carries what, and what gets parsed out of it
// ---------------------------------------------------------------------------

// TestGetUsername_ParsesAcctFromStdout pins the stream split GetUsername
// depends on. Measured against the real /usr/bin/security: `find-generic-password
// -g` writes the attribute dump — including the "acct" line GetUsername parses
// — to *stdout*, and only the `password: "..."` line to stderr. runSecurity
// returns stdout, so GetUsername sees the account. The stand-in reproduces
// both streams so that a future change routing stderr into the parsed output
// would still pass, while a change dropping stdout would not.
//
// Before this test the only coverage of a *successful* lookup was gated
// behind SECRET_LIVE_KEYCHAIN_TEST=1 and so never ran in CI — which is why
// the split's correctness was an open question for eight days despite green
// CI on main (issue #36, finding 1).
func TestGetUsername_ParsesAcctFromStdout(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: attributeDump("alice"), stderr: `password: "s3cr3t"` + "\n"},
	})

	got, err := k.GetUsername("example-service")
	if err != nil {
		t.Fatalf("GetUsername() error = %v, want the account name", err)
	}
	if got != "alice" {
		t.Errorf("GetUsername() = %q, want %q", got, "alice")
	}
}

// TestGetUsername_ParsesHexEncodedAcct covers the 0x… rendering security uses
// for non-ASCII attribute values.
func TestGetUsername_ParsesHexEncodedAcct(t *testing.T) {
	t.Parallel()
	dump := "class: \"genp\"\nattributes:\n    \"acct\"<blob>=0x616263  \"abc\"\n"
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: dump},
	})

	got, err := k.GetUsername("example-service")
	if err != nil {
		t.Fatalf("GetUsername() error = %v", err)
	}
	if got != "abc" {
		t.Errorf("GetUsername() = %q, want %q", got, "abc")
	}
}

// TestGetPassword_ReturnsSecret pins the -w path: measured against the real
// binary, `find-generic-password -w` writes the bare password to stdout with
// a trailing newline, which GetPassword must strip.
func TestGetPassword_ReturnsSecret(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -w": {stdout: "s3cr3t\n"},
	})

	got, err := k.GetPassword("example-service")
	if err != nil {
		t.Fatalf("GetPassword() error = %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("GetPassword() = %q, want %q", got, "s3cr3t")
	}
}

// TestGetUsername_UnparsableOutput covers a lookup that succeeded but whose
// output carries no usable "acct" line. That is "could not parse", not
// "absent" — returning *ErrNotFound here would tell cmd/set.go the credential
// is safe to overwrite (issue #36, S2).
func TestGetUsername_UnparsableOutput(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: "class: \"genp\"\nattributes:\n    \"svce\"<blob>=\"example-service\"\n"},
	})

	_, err := k.GetUsername("example-service")
	assertUnavailable(t, "GetUsername() on output with no acct attribute", err)
}

// TestGetUsername_MalformedHexAcct covers a hex-encoded "acct" that does not
// decode. hexDecode's error used to be dropped on the floor and the loop
// continued, ending in *ErrNotFound (issue #36, S3).
func TestGetUsername_MalformedHexAcct(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: "attributes:\n    \"acct\"<blob>=0x616\n"},
	})

	_, err := k.GetUsername("example-service")
	assertUnavailable(t, "GetUsername() on a malformed hex acct attribute", err)
}

// ---------------------------------------------------------------------------
// Classification: not-found vs could-not-read, and the fallback semantics
// ---------------------------------------------------------------------------

// TestGetPassword_NotFound covers a service that is genuinely absent from
// both the generic- and internet-password classes. It drives the stand-in
// rather than a real scratch keychain: the previous version called
// /usr/bin/security through an unbounded CombinedOutput() to build one, which
// is the very unbounded call PR #31 was dispatched to eliminate (issue #36,
// T3). The real-keychain version survives, opt-in, as
// TestGetPassword_NotFound_Live.
func TestGetPassword_NotFound(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, nil) // no scripted responses: everything misses

	_, err := k.GetPassword("does-not-exist")
	assertNotFound(t, "GetPassword() for an absent service", err)
}

// TestGetPassword_NotFoundByExitCodeAlone pins the exit-code half of the
// not-found signal: exit 44 with no stderr at all is still a definitive miss.
func TestGetPassword_NotFoundByExitCodeAlone(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -w":  {exitCode: secItemNotFoundExitCode},
		"find-internet-password -w": {exitCode: secItemNotFoundExitCode},
	})

	_, err := k.GetPassword("does-not-exist")
	assertNotFound(t, "GetPassword() against exit 44 with no stderr", err)
}

// TestGetPassword_NotFoundByMessageAlone pins the other half: security's own
// not-found diagnostic is a definitive miss even if the exit code is not 44.
// The two signals are accepted independently so that a change to either one
// degrades gracefully instead of turning every miss into a hard failure
// (issue #36, finding 4).
func TestGetPassword_NotFoundByMessageAlone(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -w":  {exitCode: 1, stderr: notFoundStderr + "\n"},
		"find-internet-password -w": {exitCode: 1, stderr: notFoundStderr + "\n"},
	})

	_, err := k.GetPassword("does-not-exist")
	assertNotFound(t, "GetPassword() against security's not-found message on a non-44 exit", err)
}

// TestGetPassword_FallsBackToInternetPassword covers the generic→internet
// fallback: a definitive miss in the generic class must be retried against
// the internet-password class.
func TestGetPassword_FallsBackToInternetPassword(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -w":  {exitCode: secItemNotFoundExitCode},
		"find-internet-password -w": {stdout: "from-internet\n"},
	})

	got, err := k.GetPassword("example-service")
	if err != nil {
		t.Fatalf("GetPassword() error = %v, want the internet-password fallback to answer", err)
	}
	if got != "from-internet" {
		t.Errorf("GetPassword() = %q, want %q", got, "from-internet")
	}
}

// TestGetPassword_DoesNotFallBackAfterRealFailure pins the semantic PR #31
// changed and asked a second pair of eyes to check: when the generic query
// fails for a reason other than a definitive miss, the internet-password
// query must not be attempted, because a hit there would not answer the
// question the caller asked. The stand-in would happily return a password
// from the fallback; the correct result is still *ErrUnavailable.
//
// The scripted failure is exit 152 with *completely empty* stderr, which is
// what a locked keychain holding the requested item was measured to do
// against the real binary. That makes this test also the coverage for the
// empty-stderr branch of securityFailureDetail: with nothing on stderr, the
// exit code is the only diagnostic there is, so the assertion below requires
// it to reach the user.
func TestGetPassword_DoesNotFallBackAfterRealFailure(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -w":  {exitCode: securityLockedExitCode},
		"find-internet-password -w": {stdout: "should-never-be-returned\n"},
	})

	got, err := k.GetPassword("example-service")
	if got != "" {
		t.Fatalf("GetPassword() = %q; the internet-password fallback ran after a non-miss failure", got)
	}
	unavailable := assertUnavailable(t, "GetPassword() against a locked-keychain exit", err)
	if !strings.Contains(unavailable.Reason, strconv.Itoa(securityLockedExitCode)) {
		t.Errorf("ErrUnavailable.Reason = %q, want it to name the observed exit code %d", unavailable.Reason, securityLockedExitCode)
	}
}

// TestGetPassword_MissingSecurityBinary exercises the "security binary itself
// cannot be run" path, which never produces an *exec.ExitError and so must
// not be classified as errItemNotFound.
//
// The previous version of this test ran a nonexistent binary through
// exec.Command directly and asserted that Go returns a non-*exec.ExitError:
// it never called into this package at all, so it would not have failed if
// the classification here regressed (issue #36, finding 3).
func TestGetPassword_MissingSecurityBinary(t *testing.T) {
	t.Parallel()
	k := newMissingBinaryKeychain(t)

	_, err := k.GetPassword("example-service")
	assertUnavailable(t, "GetPassword() with a missing security binary", err)
}

// TestGetUsername_DoesNotLeakPasswordIntoError covers the one invocation that
// asks security to print a secret (-g). cmd/gitcredential.go documents that
// no error path in this package interpolates a password value; failure
// diagnostics interpolate stderr, so the password line is redacted first
// (issue #36, S7).
func TestGetUsername_DoesNotLeakPasswordIntoError(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {
			exitCode: 1,
			stderr:   "password: \"hunter2\"\nsecurity: something went wrong\n",
		},
	})

	_, err := k.GetUsername("example-service")
	unavailable := assertUnavailable(t, "GetUsername() against a failing -g invocation", err)
	if strings.Contains(unavailable.Reason, "hunter2") {
		t.Fatalf("ErrUnavailable.Reason leaked the password: %q", unavailable.Reason)
	}
	if !strings.Contains(unavailable.Reason, "redacted") {
		t.Errorf("ErrUnavailable.Reason = %q, want the password line redacted rather than dropped", unavailable.Reason)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// TestDelete_NotFound covers a service absent from both classes: that is the
// one case in which Delete may report *ErrNotFound.
func TestDelete_NotFound(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, nil)

	assertNotFound(t, "Delete() for an absent service", k.Delete("does-not-exist"))
}

// TestDelete_UnreadableIsNotNotFound is the regression test for issue #36's
// second HIGH finding: Delete used to collapse *every* failure into
// *ErrNotFound. Its callers act on that. cmd/gitcredential.go suppresses
// *ErrNotFound from Delete entirely in both its store and erase paths, so a
// `git credential reject` against a locked keychain reported success having
// deleted nothing; cmd/set.go degrades to a warning it would never print.
//
// The stand-in also scripts delete-internet-password to succeed: a Delete
// that fell through to it after a non-miss failure would return nil and pass
// a weaker version of this test.
func TestDelete_UnreadableIsNotNotFound(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"delete-generic-password":  {exitCode: securityLockedExitCode},
		"delete-internet-password": {exitCode: 0},
	})

	err := k.Delete("example-service")
	unavailable := assertUnavailable(t, "Delete() against a locked keychain", err)
	if !strings.Contains(unavailable.Reason, strconv.Itoa(securityLockedExitCode)) {
		t.Errorf("ErrUnavailable.Reason = %q, want it to name the observed exit code %d", unavailable.Reason, securityLockedExitCode)
	}
}

// TestDelete_InternetPasswordFailureIsNotNotFound covers the same collapse on
// the second leg: a definitive miss in the generic class followed by a real
// failure in the internet class is still "could not tell".
func TestDelete_InternetPasswordFailureIsNotNotFound(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"delete-generic-password":  {exitCode: secItemNotFoundExitCode},
		"delete-internet-password": {exitCode: securityLockedExitCode},
	})

	assertUnavailable(t, "Delete() with a failing internet-password leg", k.Delete("example-service"))
}

// TestDelete_Succeeds covers the ordinary path, and
// TestDelete_FallsBackToInternetPassword the generic→internet fallback.
func TestDelete_Succeeds(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"delete-generic-password": {exitCode: 0},
	})

	if err := k.Delete("example-service"); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
}

func TestDelete_FallsBackToInternetPassword(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"delete-generic-password":  {exitCode: secItemNotFoundExitCode},
		"delete-internet-password": {exitCode: 0},
	})

	if err := k.Delete("example-service"); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
}

// TestDelete_MissingSecurityBinary mirrors TestGetPassword_MissingSecurityBinary.
func TestDelete_MissingSecurityBinary(t *testing.T) {
	t.Parallel()
	assertUnavailable(t, "Delete() with a missing security binary", newMissingBinaryKeychain(t).Delete("example-service"))
}

// ---------------------------------------------------------------------------
// IsAvailable
// ---------------------------------------------------------------------------

// TestIsAvailable_Succeeds covers the ordinary path.
func TestIsAvailable_Succeeds(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"show-keychain-info": {exitCode: 0},
	})

	if err := k.IsAvailable(); err != nil {
		t.Fatalf("IsAvailable() error = %v, want nil", err)
	}
}

// TestIsAvailable_ReportsTheActualCause covers issue #36's S5: IsAvailable
// runs before every subcommand, so its message is the most-seen error in the
// product, and it used to assert "keychain locked" whatever had gone wrong.
func TestIsAvailable_ReportsTheActualCause(t *testing.T) {
	t.Parallel()

	t.Run("locked keychain names the observed exit code", func(t *testing.T) {
		t.Parallel()
		k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
			"show-keychain-info": {exitCode: securityLockedExitCode},
		})
		unavailable := assertUnavailable(t, "IsAvailable() against a locked keychain", k.IsAvailable())
		if !strings.Contains(unavailable.Reason, strconv.Itoa(securityLockedExitCode)) {
			t.Errorf("Reason = %q, want it to name exit code %d", unavailable.Reason, securityLockedExitCode)
		}
		if !strings.Contains(unavailable.Reason, "locked") {
			t.Errorf("Reason = %q, want the locked-keychain hint", unavailable.Reason)
		}
	})

	t.Run("a non-lock failure names its own cause", func(t *testing.T) {
		t.Parallel()
		k := newMissingBinaryKeychain(t)
		unavailable := assertUnavailable(t, "IsAvailable() with a missing security binary", k.IsAvailable())
		// The old message was the bare string "keychain locked — cannot
		// retrieve secrets non-interactively" whatever had gone wrong, so the
		// real cause never reached the user at all.
		if !strings.Contains(unavailable.Reason, k.security) {
			t.Errorf("Reason = %q, want it to name the security binary it could not run (%s)", unavailable.Reason, k.security)
		}
	})
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestList_ParsesDumpKeychain(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"dump-keychain": {stdout: "class: \"genp\"\nattributes:\n    \"svce\"<blob>=\"beta\"\nclass: \"inet\"\nattributes:\n    \"srvr\"<blob>=\"alpha\"\n"},
	})

	got, err := k.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	want := []string{"alpha", "beta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List() = %v, want %v", got, want)
	}
}

func TestList_FailureIsUnavailable(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"dump-keychain": {exitCode: securityLockedExitCode},
	})

	_, err := k.List()
	assertUnavailable(t, "List() against a locked keychain", err)
}

// ---------------------------------------------------------------------------
// Timeout / unresponsive security
// ---------------------------------------------------------------------------

// TestGetPassword_LockedKeychain reproduces the data-loss scenario from issue
// #30: an existing credential that cannot be *read* because the keychain is
// locked must not be reported as *ErrNotFound (which a caller would treat as
// "safe to overwrite"). The real-lock reproduction still exists, opt-in, as
// TestGetPassword_LockedKeychain_Live below.
func TestGetPassword_LockedKeychain(t *testing.T) {
	t.Parallel()
	k := newHangingKeychain(t)

	start := time.Now()
	_, err := k.GetPassword("example-service")
	elapsed := time.Since(start)

	// Asserted against the injected timeout, not an unrelated constant: the
	// child is killed directly, so the only slack over hangTimeout is process
	// start-up. A call that was not bounded at all would run for 300s.
	if limit := 10 * hangTimeout; elapsed > limit {
		t.Fatalf("GetPassword() took %s against an unresponsive security binary, want it bounded near the %s timeout (limit %s)", elapsed, hangTimeout, limit)
	}
	assertUnavailable(t, "GetPassword() against an unresponsive security binary", err)
}

// TestGetUsername_LockedKeychain mirrors TestGetPassword_LockedKeychain for
// GetUsername, which has the same shape per issue #30.
func TestGetUsername_LockedKeychain(t *testing.T) {
	t.Parallel()
	k := newHangingKeychain(t)

	start := time.Now()
	_, err := k.GetUsername("example-service")
	elapsed := time.Since(start)

	if limit := 10 * hangTimeout; elapsed > limit {
		t.Fatalf("GetUsername() took %s against an unresponsive security binary, want it bounded near the %s timeout (limit %s)", elapsed, hangTimeout, limit)
	}
	assertUnavailable(t, "GetUsername() against an unresponsive security binary", err)
}

// TestDelete_UnresponsiveKeychain is the timeout half of issue #36's second
// HIGH finding: a Delete that never gets an answer is not a Delete that found
// nothing to remove.
func TestDelete_UnresponsiveKeychain(t *testing.T) {
	t.Parallel()
	k := newHangingKeychain(t)

	start := time.Now()
	err := k.Delete("example-service")
	elapsed := time.Since(start)

	if limit := 10 * hangTimeout; elapsed > limit {
		t.Fatalf("Delete() took %s against an unresponsive security binary, want it bounded near the %s timeout (limit %s)", elapsed, hangTimeout, limit)
	}
	assertUnavailable(t, "Delete() against an unresponsive security binary", err)
}

// ---------------------------------------------------------------------------
// Opt-in tests against a real keychain
// ---------------------------------------------------------------------------

// newScratchKeychain creates a throwaway keychain in a temp directory,
// unlocked and populated with one generic-password item, and returns a
// *Keychain for it. It is never added to the user's keychain search list, so
// it cannot interfere with (or be interfered with by) the real login
// keychain. Only the opt-in tests below use it: it calls the real
// /usr/bin/security, which is the unbounded, environment-dependent I/O that
// has no business running on every push.
func newScratchKeychain(t *testing.T) (k *Keychain, service string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scratch.keychain-db")
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

	run(securityBinary, "create-keychain", "-p", pass, path)
	t.Cleanup(func() { _ = exec.Command(securityBinary, "delete-keychain", path).Run() })
	run(securityBinary, "unlock-keychain", "-p", pass, path)
	run(securityBinary, "add-generic-password",
		"-s", service, "-a", "scratch-account", "-w", "scratch-password",
		"-T", securityBinary, path)

	return &Keychain{keychainPath: path, security: securityBinary, timeout: securityCommandTimeout}, service
}

func skipUnlessLive(t *testing.T) {
	t.Helper()
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to run against a real scratch keychain")
	}
}

// TestGetPassword_NotFound_Live is the real-keychain counterpart of
// TestGetPassword_NotFound. It is the only automated check that
// secItemNotFoundExitCode is still what /usr/bin/security actually returns,
// so it is worth running by hand when the classification is touched.
func TestGetPassword_NotFound_Live(t *testing.T) {
	skipUnlessLive(t)
	k, _ := newScratchKeychain(t)

	_, err := k.GetPassword("secret-issue30-does-not-exist")
	assertNotFound(t, "GetPassword() for an absent service", err)
}

// TestDelete_NotFound_Live is the real-keychain counterpart of
// TestDelete_NotFound, and the only automated check that
// `security delete-generic-password` reports a missing item with
// secItemNotFoundExitCode the way `find-generic-password` does. That symmetry
// is assumed, not measured: if it does not hold, Delete reports
// *ErrUnavailable for a genuine miss — noisier than before, but never the
// other way round.
func TestDelete_NotFound_Live(t *testing.T) {
	skipUnlessLive(t)
	k, _ := newScratchKeychain(t)

	assertNotFound(t, "Delete() for an absent service", k.Delete("secret-issue30-does-not-exist"))
}

// TestGetUsername_Live is the real-keychain counterpart of
// TestGetUsername_ParsesAcctFromStdout: it is what would catch security
// moving its attribute dump to the other stream on some future macOS.
func TestGetUsername_Live(t *testing.T) {
	skipUnlessLive(t)
	k, service := newScratchKeychain(t)

	got, err := k.GetUsername(service)
	if err != nil {
		t.Fatalf("GetUsername() error = %v", err)
	}
	if got != "scratch-account" {
		t.Errorf("GetUsername() = %q, want %q", got, "scratch-account")
	}
}

// TestGetPassword_LockedKeychain_Live reproduces issue #30 against a real,
// actually-locked scratch keychain rather than a stand-in security binary. It
// is opt-in (SECRET_LIVE_KEYCHAIN_TEST=1) rather than unconditional,
// following the precedent set for the D-Bus backend in PR #29
// (SECRET_LIVE_DBUS_TEST=1): this is the exact call that hung CI for ten
// minutes on the headless macos-latest runner before the timeout existed, and
// even bounded by it, it is slow, real, environment-dependent I/O. The
// always-on regression coverage for the product fix is
// TestGetPassword_LockedKeychain above.
func TestGetPassword_LockedKeychain_Live(t *testing.T) {
	skipUnlessLive(t)
	k, service := newScratchKeychain(t)

	if _, err := k.GetPassword(service); err != nil {
		t.Fatalf("GetPassword() before locking: %v", err)
	}
	lockScratchKeychain(t, k.keychainPath)

	_, err := k.GetPassword(service)
	assertUnavailable(t, "GetPassword() on a locked keychain", err)
}

// TestGetUsername_LockedKeychain_Live mirrors
// TestGetPassword_LockedKeychain_Live for GetUsername.
func TestGetUsername_LockedKeychain_Live(t *testing.T) {
	skipUnlessLive(t)
	k, service := newScratchKeychain(t)

	if _, err := k.GetUsername(service); err != nil {
		t.Fatalf("GetUsername() before locking: %v", err)
	}
	lockScratchKeychain(t, k.keychainPath)

	_, err := k.GetUsername(service)
	assertUnavailable(t, "GetUsername() on a locked keychain", err)
}

// TestDelete_LockedKeychain_Live is the real-keychain counterpart of
// TestDelete_UnreadableIsNotNotFound.
func TestDelete_LockedKeychain_Live(t *testing.T) {
	skipUnlessLive(t)
	k, service := newScratchKeychain(t)
	lockScratchKeychain(t, k.keychainPath)

	assertUnavailable(t, "Delete() on a locked keychain", k.Delete(service))
}

// lockScratchKeychain locks the throwaway keychain created by
// newScratchKeychain. It takes the path rather than defaulting to anything so
// that it can only ever be pointed at a keychain the test itself made.
func lockScratchKeychain(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command(securityBinary, "lock-keychain", path).CombinedOutput()
	if err != nil {
		t.Fatalf("lock-keychain %s: %v: %s", path, err, out)
	}
}
