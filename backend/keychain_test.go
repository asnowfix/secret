//go:build darwin

package backend

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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

	got, err := parseKeychainDumpServices(dump)
	if err != nil {
		t.Fatalf("parseKeychainDumpServices() error = %v", err)
	}
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
	got, err := parseKeychainDumpServices(dump)
	if err != nil {
		t.Fatalf("parseKeychainDumpServices() error = %v", err)
	}
	want := []string{"abc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeychainDumpServices() = %v, want %v", got, want)
	}
}

func TestParseKeychainDumpServices_Empty(t *testing.T) {
	t.Parallel()
	got, err := parseKeychainDumpServices("")
	if err != nil {
		t.Fatalf("parseKeychainDumpServices() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("parseKeychainDumpServices(\"\") = %v, want empty", got)
	}
}

// TestParseKeychainDumpServices_MalformedHex pins issue #36's S3 in the
// parser it was originally left out of: an undecodable service name must fail
// the enumeration, not disappear from it. Skipping it would make `secret
// list` omit a service that `secret password <service>` still resolves, with
// nothing anywhere saying so.
func TestParseKeychainDumpServices_MalformedHex(t *testing.T) {
	t.Parallel()
	dump := `class: "genp"
attributes:
    "svce"<blob>="visible"
class: "genp"
attributes:
    "svce"<blob>=0x616
`
	got, err := parseKeychainDumpServices(dump)
	if err == nil {
		t.Fatalf("parseKeychainDumpServices() = %v, nil error; want a failure for an undecodable service name", got)
	}
	if got != nil {
		t.Errorf("parseKeychainDumpServices() = %v on error, want no partial list", got)
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

// TestExitCodeConstants pins secItemNotFoundExitCode and securityLockedExitCode
// against literals independent of the constants themselves (issue #45, item
// 3). Every other test in this file scripts the stand-in *from* these
// constants, so a change to either declaration is otherwise invisible to the
// always-on suite: the mechanism stays pinned, but the value can drift
// unnoticed. This mirrors the discipline TestOSStatusMirrors already applies
// to its own mirrors in passwords_app_test.go.
//
// Both values are measured against the real /usr/bin/security, most recently
// against an isolated scratch keychain on 2026-09-06 (see issue #45):
// locked+absent exits 44 regardless of flag, locked+present exits 152 for a
// data read (-w or -g). A flag-less read touches only unencrypted attributes
// and exits 0 even locked, so that measurement is not evidence either way —
// findPassword always passes -w or -g (see runSecurity's callers), so the
// production path only ever sees the 44/152 split this test pins.
func TestExitCodeConstants(t *testing.T) {
	t.Parallel()
	if secItemNotFoundExitCode != 44 {
		t.Errorf("secItemNotFoundExitCode = %d, want 44 (measured against /usr/bin/security)", secItemNotFoundExitCode)
	}
	if securityLockedExitCode != 152 {
		t.Errorf("securityLockedExitCode = %d, want 152 (measured against /usr/bin/security)", securityLockedExitCode)
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

	// Every invocation records its full argument vector before answering, so
	// that tests can assert *what was queried* and not only what came back.
	// Without it the stand-in reads $1 and $2 and ignores the rest, and a
	// query against the wrong service — or one that drops the keychain path
	// and silently hits the user's default keychain search list — returns the
	// same canned answer as the correct one.
	script := "#!/bin/sh\n" +
		"{ for a in \"$@\"; do printf '%s\\n' \"$a\"; done; " +
		"printf '%s\\n' '" + standInArgvRecordEnd + "'; } >> '" + filepath.Join(dir, standInArgvLogName) + "'\n" +
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

// standInArgvLogName is the file, beside the stand-in keychain path, in which
// the stand-in records the argument vector of every invocation: one argument
// per line, each invocation terminated by standInArgvRecordEnd. It is found
// relative to Keychain.keychainPath rather than carried on the struct — that
// is production code and gains nothing from a test-only field.
//
// An argument containing a newline would be recorded as two lines. No
// argument this package passes can contain one (subcommands, flags, a service
// name and a path), and the one caller that could — Add's -w password — is
// supplied by the test itself.
const standInArgvLogName = "argv.log"

// standInArgvRecordEnd terminates one recorded invocation. It is not a string
// any security invocation could pass as an argument.
const standInArgvRecordEnd = "--end-of-argv--"

// standInInvocations returns the argument vectors the stand-in has been
// called with, in call order.
func standInInvocations(t *testing.T, k *Keychain) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(k.keychainPath), standInArgvLogName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read stand-in argv log: %v", err)
	}

	var invocations [][]string
	var current []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == standInArgvRecordEnd {
			invocations = append(invocations, current)
			current = nil
			continue
		}
		current = append(current, line)
	}
	if current != nil {
		t.Fatalf("stand-in argv log ends mid-record: %q", current)
	}
	return invocations
}

// assertInvocations asserts the exact sequence of argument vectors the
// stand-in was called with.
//
// Whole-argv equality rather than a spot check on the service name: it pins
// the subcommand, the read flag, the -s/-a/-w arguments, the keychain path
// and the order of the calls in a single assertion. Those are exactly what no
// test constrained while the stand-in looked only at $1 and $2 — deleting the
// wrong service, or querying the user's default keychain search list instead
// of the configured keychain, produced identical canned output and passed
// (issue #36 review, finding 2).
func assertInvocations(t *testing.T, k *Keychain, want [][]string) {
	t.Helper()
	got := standInInvocations(t, k)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("security was invoked as\n\t%v\nwant\n\t%v", got, want)
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
// will ever answer. Driving that through a stand-in exercises
// runSecurityBoundedCtx's own timeout/kill logic deterministically, without
// depending on real keychain/agent behavior — which is exactly what hung CI
// for ten minutes and left an orphan `security` process behind.
//
// It delegates to newHangingKeychainWithPromptTimeout with promptTimeout=0
// rather than duplicating the stand-in script: this file makes an explicit
// point elsewhere of not letting two things do the same job drift apart
// (see attributeRegexp's comment on the two dump parsers), and this pair
// used to be exactly that — byte-for-byte the same script-writing logic
// with one field added.
func newHangingKeychain(t *testing.T) *Keychain {
	t.Helper()
	return newHangingKeychainWithPromptTimeout(t, hangTimeout, 0)
}

// newHangingKeychainWithStderr is newHangingKeychain, except the stand-in
// writes msg to stderr before it hangs — standing in for a real `security`
// invocation that printed a diagnostic (e.g. "User interaction is not
// allowed") before the deadline killed it, the scenario
// runSecurityBoundedCtx's timeout branch must not discard.
//
// timeout is deliberately a parameter rather than the package's usual
// hangTimeout: it has to be generous enough that `/bin/sh`'s own startup
// plus the echo reliably completes before the deadline fires, or the test
// would flake on exactly the race it is trying to pin down rather than
// asserting the message-building logic.
func newHangingKeychainWithStderr(t *testing.T, timeout time.Duration, msg string) *Keychain {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "security")
	script := fmt.Sprintf("#!/bin/sh\necho %q 1>&2\nexec sleep 300\n", msg)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath: filepath.Join(dir, "irrelevant.keychain-db"),
		security:     binary,
		timeout:      timeout,
	}
}

// grandchildHangSeconds is how long the grandchild left behind by
// newGrandchildHangingKeychain's stand-in sleeps for. It only needs to
// outlast securityWaitDelay by a comfortable margin — long enough that a
// missing WaitDelay guard reliably blocks past the assertion's limit, short
// enough that a mutated run does not sit around for real
// newHangingKeychain-style minutes.
const grandchildHangSeconds = 20

// newGrandchildHangingKeychain returns a *Keychain whose security CLI
// backgrounds a sleep that inherits its stdout/stderr pipes and then exits
// itself almost immediately.
//
// This is deliberately not newHangingKeychain's shape. newHangingKeychain's
// script is `#!/bin/sh\nexec sleep 300`: exec replaces the shell with sleep,
// so sleep *is* the direct child, and killing it directly closes the pipes —
// the scenario securityWaitDelay exists for never arises. Here the direct
// child (the shell) exits on its own, quickly and successfully, while the
// backgrounded sleep it leaves behind keeps holding the write end of the
// inherited stdout/stderr pipes open. cmd.Wait has nothing to kill — the
// process it is waiting on already exited — but it still cannot return until
// those pipes reach EOF, which does not happen until the grandchild does.
// That is exactly the case securityWaitDelay bounds, and it is independent of
// context cancellation: nothing here ever hits k.timeout's deadline.
func newGrandchildHangingKeychain(t *testing.T) *Keychain {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "security")
	script := fmt.Sprintf("#!/bin/sh\nsleep %d &\nexit 0\n", grandchildHangSeconds)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath: filepath.Join(dir, "irrelevant.keychain-db"),
		security:     binary,
		// Generous and, unlike hangTimeout, irrelevant to what this stand-in
		// tests: the direct child exits well within it, so the context
		// deadline never fires. What is asserted below is bounded by
		// securityWaitDelay alone.
		timeout: standInTimeout,
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
//
// The reason must name the actual cause (issue #45, item 2). With the S3 fix
// reverted — the loop swallowing hexDecode's error and continuing instead of
// returning it — parseAccount still falls off the end of the loop and returns
// `no "acct" attribute in security output`, which GetUsername still wraps as
// *ErrUnavailable. Asserting only the type, as this test used to, cannot tell
// that "no attribute" cover story apart from the real "malformed hex"
// diagnosis, so the S3 fix could regress silently underneath a green test.
func TestGetUsername_MalformedHexAcct(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: "attributes:\n    \"acct\"<blob>=0x616\n"},
	})

	_, err := k.GetUsername("example-service")
	unavailable := assertUnavailable(t, "GetUsername() on a malformed hex acct attribute", err)
	if !strings.Contains(unavailable.Reason, "malformed hex") {
		t.Errorf("ErrUnavailable.Reason = %q, want it to name the malformed hex attribute rather than report a bare absence", unavailable.Reason)
	}
}

// TestGetUsername_EmptyAccount covers an item whose account attribute is
// present and empty — `"acct"<blob>=""`, which is what security prints for a
// credential stored with no username. `git credential store` can create one:
// cmd/gitcredential.go passes in.username through, and git does not guarantee
// it is set.
//
// The lookup succeeded and the attribute parsed; the value is simply empty.
// Reporting that as "could not read keychain item" made `secret login` exit 1
// on an item that reads perfectly.
func TestGetUsername_EmptyAccount(t *testing.T) {
	t.Parallel()
	dump := "class: \"genp\"\nattributes:\n    \"acct\"<blob>=\"\"\n    \"svce\"<blob>=\"example-service\"\n"
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {stdout: dump},
	})

	got, err := k.GetUsername("example-service")
	if err != nil {
		t.Fatalf("GetUsername() error = %v, want the empty account the item actually carries", err)
	}
	if got != "" {
		t.Errorf("GetUsername() = %q, want the empty string", got)
	}
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

// TestFindPassword_QueriesTheRequestedService pins the argument vector of
// both read legs: the subcommand, the flag that selects what security prints,
// the service actually asked about, and the keychain the query is scoped to.
//
// The last of those is the one with teeth. Dropping k.keychainPath does not
// fail: security then searches the user's default keychain search list, so
// the backend would quietly answer from a keychain nobody configured — and
// against a stand-in that ignores its arguments, every one of these mutations
// returned the same canned answer and passed.
func TestFindPassword_QueriesTheRequestedService(t *testing.T) {
	t.Parallel()

	t.Run("GetUsername asks for the attribute dump", func(t *testing.T) {
		t.Parallel()
		k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
			"find-generic-password -g": {stdout: attributeDump("alice")},
		})

		if _, err := k.GetUsername("example-service"); err != nil {
			t.Fatalf("GetUsername() error = %v", err)
		}
		assertInvocations(t, k, [][]string{
			{"find-generic-password", "-g", "-s", "example-service", k.keychainPath},
		})
	})

	t.Run("GetPassword asks for the password alone, and falls back in the same keychain", func(t *testing.T) {
		t.Parallel()
		k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
			"find-generic-password -w":  {exitCode: secItemNotFoundExitCode},
			"find-internet-password -w": {stdout: "from-internet\n"},
		})

		if _, err := k.GetPassword("example-service"); err != nil {
			t.Fatalf("GetPassword() error = %v", err)
		}
		assertInvocations(t, k, [][]string{
			{"find-generic-password", "-w", "-s", "example-service", k.keychainPath},
			{"find-internet-password", "-w", "-s", "example-service", k.keychainPath},
		})
	})
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
//
// It also pins securityFailureDetail's `unlock-keychain` hint (issue #45,
// item 5). GetPassword's error never passes through keychainUnavailableReason
// — that function's own, unconditional "if it is locked, run `security
// unlock-keychain %s`" suffix belongs to IsAvailable's diagnostic alone — so
// the only way this Reason can contain the hint text is if
// securityFailureDetail itself still appends it for exit 152. Removing that
// suffix in production leaves this test's exit-code assertion above green but
// fails the one below.
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
	if !strings.Contains(unavailable.Reason, "try `security unlock-keychain`") {
		t.Errorf("ErrUnavailable.Reason = %q, want the securityFailureDetail unlock-keychain hint for a locked-keychain exit", unavailable.Reason)
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

// TestGetUsername_DoesNotLeakBinaryPasswordIntoError covers security's other
// rendering of the same line: a password it cannot print as text arrives as
// `password: 0x<hex>  "<lossy>"`, which an anchored `^password: ".*"$` does
// not match at all. Both renderings must be redacted, and the diagnostic that
// explains the failure must survive the redaction.
func TestGetUsername_DoesNotLeakBinaryPasswordIntoError(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"find-generic-password -g": {
			exitCode: 1,
			stderr:   "password: 0x68756E74657232  \"hunter2\"\nsecurity: something went wrong\n",
		},
	})

	_, err := k.GetUsername("example-service")
	unavailable := assertUnavailable(t, "GetUsername() against a failing -g invocation", err)
	for _, leaked := range []string{"hunter2", "68756E74657232"} {
		if strings.Contains(unavailable.Reason, leaked) {
			t.Fatalf("ErrUnavailable.Reason leaked the password (%q): %q", leaked, unavailable.Reason)
		}
	}
	if !strings.Contains(unavailable.Reason, "redacted") {
		t.Errorf("ErrUnavailable.Reason = %q, want the password line redacted rather than dropped", unavailable.Reason)
	}
	if !strings.Contains(unavailable.Reason, "something went wrong") {
		t.Errorf("ErrUnavailable.Reason = %q, want the diagnostic to survive redaction", unavailable.Reason)
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

// TestDelete_TargetsTheRequestedService is the destructive counterpart of
// TestFindPassword_QueriesTheRequestedService, and the reason both exist: a
// Delete that names the wrong service removes a credential the caller never
// asked about, and the stand-in answered exit 0 to it just as happily as to
// the right one.
func TestDelete_TargetsTheRequestedService(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"delete-generic-password":  {exitCode: secItemNotFoundExitCode},
		"delete-internet-password": {exitCode: 0},
	})

	if err := k.Delete("example-service"); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
	assertInvocations(t, k, [][]string{
		{"delete-generic-password", "-s", "example-service", k.keychainPath},
		{"delete-internet-password", "-s", "example-service", k.keychainPath},
	})
}

// ---------------------------------------------------------------------------
// Add
// ---------------------------------------------------------------------------

// TestAdd_GrantsAccessToTheRealSecurityBinary pins the one argument in this
// file that must *not* follow the test seam. `-T /usr/bin/security` is the
// non-interactive ACL grant that AGENTS.md records as the entire reason this
// backend shells out to the security CLI instead of using cgo; passing
// k.security there would make the ACL name whatever binary the tests
// installed, and every subsequent read of that item would prompt.
//
// Add had no test at all, so both that and the -s/-a/-w vector were free to
// change silently.
func TestAdd_GrantsAccessToTheRealSecurityBinary(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"add-generic-password": {exitCode: 0},
	})
	if k.security == securityBinary {
		t.Fatal("the stand-in is the real security binary; this test cannot tell -T apart from the test seam")
	}

	if err := k.Add("example-service", "alice", "s3cr3t"); err != nil {
		t.Fatalf("Add() error = %v, want nil", err)
	}
	assertInvocations(t, k, [][]string{
		{"add-generic-password", "-s", "example-service", "-a", "alice", "-w", "s3cr3t", "-T", securityBinary, k.keychainPath},
	})
}

// TestAdd_FailureIsUnavailable pins Add's error type. No caller does errors.As
// on it today, so nothing breaks if it degrades to a bare fmt.Errorf — but
// wincred.go and libsecret.go both return *ErrUnavailable from Add, and a
// backend that quietly stops honouring the shared contract is found by the
// first caller that starts relying on it.
//
// The absent-service subtest pins the other half: a write has no meaningful
// "not found" outcome, so Add must not classify one even when security
// reports a definitive miss.
func TestAdd_FailureIsUnavailable(t *testing.T) {
	t.Parallel()

	t.Run("locked keychain", func(t *testing.T) {
		t.Parallel()
		k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
			"add-generic-password": {exitCode: securityLockedExitCode},
		})
		assertUnavailable(t, "Add() against a locked keychain", k.Add("example-service", "alice", "s3cr3t"))
	})

	t.Run("definitive miss is still not *ErrNotFound", func(t *testing.T) {
		t.Parallel()
		k := newStandInKeychain(t, standInTimeout, nil)
		assertUnavailable(t, "Add() against a not-found exit", k.Add("example-service", "alice", "s3cr3t"))
	})

	t.Run("missing security binary", func(t *testing.T) {
		t.Parallel()
		k := newMissingBinaryKeychain(t)
		assertUnavailable(t, "Add() with a missing security binary", k.Add("example-service", "alice", "s3cr3t"))
	})
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

	// An unresponsive security binary names itself as a timeout rather than
	// falling back to the same generic phrasing used for every other
	// unclassified cause (issue #45, item 4). Checking for the bare substring
	// "timeout" would not discriminate here: the underlying error text
	// (errSecurityTimeout wrapped with the command and configured duration)
	// already contains that word regardless of which branch produced the
	// final message, since the generic fallback interpolates the same
	// wrapped error via %v. What is unique to the correct classification is
	// keychainTimeoutReason's own phrasing, which the fallback never
	// produces.
	//
	// The assertion is on "access-control prompt" rather than the old
	// "agent able to answer" substring: issue #44 fixed keychainTimeoutReason
	// unconditionally blaming a lock for what can just as well be an ACL
	// authorization prompt (measured hands-on with the keychain demonstrably
	// unlocked per `security show-keychain-info`), so the message now hedges
	// between both causes instead of asserting one. "access-control prompt"
	// is still unique to keychainTimeoutReason's own phrasing — it never
	// appears in errSecurityTimeout's wrapped text, so this still
	// discriminates the timeout classification from the generic fallback the
	// same way the old assertion did.
	t.Run("an unresponsive keychain names it as a timeout", func(t *testing.T) {
		t.Parallel()
		k := newHangingKeychain(t)
		unavailable := assertUnavailable(t, "IsAvailable() against an unresponsive security binary", k.IsAvailable())
		if !strings.Contains(unavailable.Reason, "access-control prompt") {
			t.Errorf("Reason = %q, want it to name the timeout rather than fall back to the generic could-not-open phrasing", unavailable.Reason)
		}
	})
}

// TestRunSecurityBounded_TimeoutIncludesChildStderr covers a review finding
// on #68: a security invocation that raised a prompt can write a diagnostic
// (e.g. "User interaction is not allowed") to stderr before the deadline
// kills it, and that line is the one piece of evidence able to tell an
// unlock prompt apart from an ACL prompt — runSecurityBounded's timeout
// branch used to discard it in favour of errSecurityTimeout's generic
// wrapping.
func TestRunSecurityBounded_TimeoutIncludesChildStderr(t *testing.T) {
	// Deliberately not t.Parallel(): this test's correctness depends on
	// /bin/sh actually starting and writing to stderr before the deadline
	// fires, and running alongside a burst of sibling tests that fork their
	// own stand-in processes made that race flake even at 800ms. Running
	// alone removes the contention; the generous timeout below is the
	// remaining margin.
	const (
		diagnostic = "security: SecKeychainSearchCopyNext: User interaction is not allowed."
		// Long enough for /bin/sh's own startup plus the echo to reliably
		// complete before the deadline fires, even under CPU contention;
		// short enough this test stays fast.
		timeout = 2 * time.Second
	)
	k := newHangingKeychainWithStderr(t, timeout, diagnostic)
	unavailable := assertUnavailable(t, "GetPassword() against a prompt that wrote to stderr before timing out", func() error {
		_, err := k.GetPassword("whatever")
		return err
	}())
	if !strings.Contains(unavailable.Reason, diagnostic) {
		t.Errorf("Reason = %q, want it to include the child's stderr diagnostic %q", unavailable.Reason, diagnostic)
	}
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

// TestList_MalformedServiceNameIsUnavailable is
// TestParseKeychainDumpServices_MalformedHex through the backend: an
// enumeration this package cannot fully parse is reported as unavailable, not
// returned as a shorter list that looks complete.
func TestList_MalformedServiceNameIsUnavailable(t *testing.T) {
	t.Parallel()
	k := newStandInKeychain(t, standInTimeout, map[string]securityResponse{
		"dump-keychain": {stdout: "class: \"genp\"\nattributes:\n    \"svce\"<blob>=\"visible\"\nclass: \"genp\"\nattributes:\n    \"svce\"<blob>=0x616\n"},
	})

	services, err := k.List()
	assertUnavailable(t, "List() against an undecodable service name", err)
	if services != nil {
		t.Errorf("List() = %v alongside an error, want no partially-parsed list", services)
	}
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

// TestRunSecurity_WaitDelayBoundsGrandchildHoldingPipe pins the mechanism
// securityWaitDelay actually exists for (issue #45, item 1). It does not use
// newHangingKeychain: that stand-in's `exec sleep 300` makes sleep the direct
// child, so killing it closes the pipes directly and the guard is never
// exercised. Here the direct child (the shell) exits on its own — nothing is
// killed, and k.timeout's context deadline never fires — while a backgrounded
// grandchild keeps the inherited stdout/stderr pipes open. Removing
// `cmd.WaitDelay = securityWaitDelay` from runSecurity leaves this test green
// against every other case in this file, but makes GetPassword here take the
// full grandchildHangSeconds instead of stopping near securityWaitDelay.
func TestRunSecurity_WaitDelayBoundsGrandchildHoldingPipe(t *testing.T) {
	t.Parallel()
	k := newGrandchildHangingKeychain(t)

	start := time.Now()
	_, err := k.GetPassword("example-service")
	elapsed := time.Since(start)

	// Comfortably over securityWaitDelay (so the correctly-guarded call, which
	// stops close to it plus process-scheduling slack, never flakes) and
	// comfortably under grandchildHangSeconds (so a regression is caught in
	// well under the full sleep rather than at it).
	if limit := 10 * securityWaitDelay; elapsed > limit {
		t.Fatalf("GetPassword() took %s against a grandchild holding the inherited pipe, want it bounded near securityWaitDelay (%s) (limit %s)", elapsed, securityWaitDelay, limit)
	}
	assertUnavailable(t, "GetPassword() against a grandchild holding the inherited pipe", err)
}

// ---------------------------------------------------------------------------
// Interactivity and the prompt timeout (issue #67)
// ---------------------------------------------------------------------------

// newHangingKeychainWithPromptTimeout is newHangingKeychain's counterpart
// for exercising the choice a prompting call makes between k.timeout and
// k.promptTimeout. Both bounds are supplied explicitly and kept short here —
// unlike NewKeychain's real wiring, where the long bound is
// humanResponseTimeout — so that covering the choice between them never
// sleeps anywhere near that long and never depends on whether the machine
// running `go test` has a terminal on stderr: nothing here calls
// NewKeychain or isInteractive at all.
func newHangingKeychainWithPromptTimeout(t *testing.T, timeout, promptTimeout time.Duration) *Keychain {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "security")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath:  filepath.Join(dir, "irrelevant.keychain-db"),
		security:      binary,
		timeout:       timeout,
		promptTimeout: promptTimeout,
		// interactive tracks promptTimeout here deliberately: this helper's
		// whole point is to simulate what newKeychain would have produced
		// for a given interactivity answer, and newKeychain always sets the
		// two together (see Keychain.interactive's doc comment for why
		// production code must not infer one from the other in general).
		interactive: promptTimeout != 0,
	}
}

// assertPromptTimeout is assertUnavailable's stricter sibling for the
// hanging-stand-in tests in this section: it also asserts the failure is
// actually a timeout, not merely *ErrUnavailable. assertUnavailable's type
// check alone is satisfied by a transient child-spawn failure too — a
// fork/exec race or ETXTBSY on the just-written stand-in script returns in
// milliseconds and is also *ErrUnavailable — which made
// TestRunSecurityPrompt_AllPromptingCallSitesUsePromptTimeout fail on its
// elapsed-time assertion alone roughly once per four full -race runs
// (review round 1 on #68), a mystery red build rather than a message
// naming the actual mismatch.
func assertPromptTimeout(t *testing.T, what string, err error) *ErrUnavailable {
	t.Helper()
	unavailable := assertUnavailable(t, what, err)
	if !strings.Contains(unavailable.Reason, errSecurityTimeout.Error()) {
		t.Errorf("%s: Reason = %q, want it to report a timeout (contains %q); a fast failure for another reason (e.g. a transient spawn error) passes the *ErrUnavailable type check but should fail this",
			what, unavailable.Reason, errSecurityTimeout.Error())
	}
	return unavailable
}

// TestNewKeychain_PromptTimeout pins newKeychain's wiring of promptTimeout
// to its injected interactive func's answer. It calls newKeychain directly
// with a fixed func literal rather than NewKeychain with isInteractive
// swapped out from under it: isInteractive is a plain func precisely so
// this test needs no package-level mutable state, and can therefore run in
// parallel like every other test in this file (see isInteractive's doc
// comment in keychain.go, and securityBinary's just above it, for why that
// matters here).
func TestNewKeychain_PromptTimeout(t *testing.T) {
	t.Parallel()

	if k := newKeychain(func() bool { return true }); k.promptTimeout != humanResponseTimeout {
		t.Errorf("newKeychain(always-interactive).promptTimeout = %s, want humanResponseTimeout (%s)",
			k.promptTimeout, humanResponseTimeout)
	}
	if k := newKeychain(func() bool { return false }); k.promptTimeout != 0 {
		t.Errorf("newKeychain(never-interactive).promptTimeout = %s, want 0 (same as k.timeout)", k.promptTimeout)
	}
}

// TestRunSecurityPrompt_AllPromptingCallSitesUsePromptTimeout proves every
// Backend method that can reach a prompting security subcommand is actually
// bounded by k.promptTimeout when it is set, not merely that the code
// compiles: k.timeout is set far shorter than the prompt bound, so a call
// that returned near k.timeout instead would fail the lower-bound
// assertion below.
//
// This covers six Backend methods (GetPassword and GetUsername share
// findPassword; Add, Delete, List and IsAvailable each make their own),
// independently, rather than GetPassword alone: review round 1 on #68
// found this suite's real gap was structural, not a missing assertion —
// nothing joined NewKeychain's/promptTimeout's decision to a call that
// observes it for four of the six then-fixed call sites, so reverting
// add-generic-password, delete-generic-password, delete-internet-password
// and dump-keychain from a prompting bound back to the machine one passed
// the whole suite green. A per-method entry here closes that gap for
// add-generic-password, delete-generic-password and dump-keychain.
//
// It does NOT close it for find-internet-password or delete-internet-password.
// The stand-in this test uses (newHangingKeychainWithPromptTimeout) hangs
// on every subcommand unconditionally, so GetPassword/GetUsername's Delete's
// first call (find-generic-password, delete-generic-password) always times
// out rather than returning a definitive miss — and only a definitive miss
// makes findPassword/Delete try their second subcommand at all (see each
// method's own comment on why). This test's Delete and GetPassword/
// GetUsername entries therefore only ever exercise the generic-password
// leg; review round 2 confirmed reverting the internet-password leg
// specifically leaves this test, and the rest of the suite, green.
// TestFindPassword_SharesOneDeadlineAcrossBothCalls and
// TestDelete_SharesOneDeadlineAcrossBothCalls close that gap instead, with
// a stand-in built to actually reach the second call.
func TestRunSecurityPrompt_AllPromptingCallSitesUsePromptTimeout(t *testing.T) {
	t.Parallel()
	const (
		shortTimeout = 50 * time.Millisecond
		promptBound  = 300 * time.Millisecond
		// Generous relative to promptBound and independent of it, rather
		// than a small multiplier: review round 1 flagged upper bounds at
		// or below securityWaitDelay (1s) as liable to fail outright on any
		// run where WaitDelay's pipe-close wait engages at all, even though
		// this stand-in's "exec sleep 300" shape (direct child replaced, no
		// grandchild) means it normally does not.
		limit = promptBound + 5*securityWaitDelay
	)
	tests := []struct {
		name string
		call func(k *Keychain) error
	}{
		{"GetPassword", func(k *Keychain) error { _, err := k.GetPassword("x"); return err }},
		{"GetUsername", func(k *Keychain) error { _, err := k.GetUsername("x"); return err }},
		{"Add", func(k *Keychain) error { return k.Add("x", "acct", "pw") }},
		{"Delete", func(k *Keychain) error { return k.Delete("x") }},
		{"List", func(k *Keychain) error { _, err := k.List(); return err }},
		{"IsAvailable", func(k *Keychain) error { return k.IsAvailable() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k := newHangingKeychainWithPromptTimeout(t, shortTimeout, promptBound)

			start := time.Now()
			err := tt.call(k)
			elapsed := time.Since(start)

			if elapsed < promptBound {
				t.Errorf("%s: returned after %s, want at least promptBound (%s): this call must be bounded by k.promptTimeout, not k.timeout (%s)",
					tt.name, elapsed, promptBound, shortTimeout)
			}
			if elapsed > limit {
				t.Fatalf("%s: took %s against a hanging security binary, want it bounded near promptBound (%s) (limit %s)", tt.name, elapsed, promptBound, limit)
			}
			assertPromptTimeout(t, tt.name+"() against a hanging security binary with promptTimeout set", err)
		})
	}
}

// TestRunSecurityPrompt_ZeroPromptTimeoutFallsBackToTimeout proves the
// documented meaning of promptTimeout == 0: identical to k.timeout, which is
// what every pre-#67 &Keychain{...} test literal in this file (none of
// which set promptTimeout) has always gotten and must keep getting.
//
// The lower bound is the assertion that actually pins this: deleting the
// fallback in runSecurity/promptOperationContext, so promptTimeout==0
// is passed literally to context.WithTimeout as an already-dead context,
// returns in microseconds and previously passed this test outright — the
// suite only went red through unrelated pre-existing literals that happen
// to break with a 0s bound, an accident that would evaporate the moment any
// of them gained a promptTimeout (review round 1 on #68).
func TestRunSecurityPrompt_ZeroPromptTimeoutFallsBackToTimeout(t *testing.T) {
	t.Parallel()
	const shortTimeout = 100 * time.Millisecond
	k := newHangingKeychainWithPromptTimeout(t, shortTimeout, 0)

	start := time.Now()
	_, err := k.GetPassword("irrelevant")
	elapsed := time.Since(start)

	if elapsed < shortTimeout {
		t.Errorf("GetPassword() returned after %s with promptTimeout=0, want at least k.timeout (%s): promptTimeout=0 must fall back to k.timeout, not to an already-dead zero-duration context.WithTimeout",
			elapsed, shortTimeout)
	}
	if limit := shortTimeout + 5*securityWaitDelay; elapsed > limit {
		t.Fatalf("GetPassword() took %s with promptTimeout=0, want it bounded near k.timeout (%s) (limit %s)", elapsed, shortTimeout, limit)
	}
	unavailable := assertPromptTimeout(t, "GetPassword() against a hanging security binary with promptTimeout=0", err)
	if !strings.Contains(unavailable.Reason, "not detected as a terminal") {
		t.Errorf("Reason = %q, want the non-interactive hint since promptTimeout=0 means this call was not given a prompt bound", unavailable.Reason)
	}
}

// TestAddAndList_TimeoutGetsSameDiagnosticAsReadDelete proves Add and List
// route a security timeout through the same message construction
// classifySecurityError gives GetPassword/GetUsername/Delete
// (securityErrorReason, ultimately keychainPromptTimeoutReason), rather
// than building their own bare "%v" wrapping. Before review round 1 on #68,
// Add and List called runSecurityPrompt and then constructed their
// *ErrUnavailable inline, bypassing classifySecurityError entirely — so a
// script running `secret set`/`secret list` behind a timed-out dialog got
// neither the lock-vs-ACL disambiguation nor the interactivity hint,
// silently reintroducing #67's complaint on the write/list path after it
// was fixed on read/delete.
func TestAddAndList_TimeoutGetsSameDiagnosticAsReadDelete(t *testing.T) {
	t.Parallel()
	const shortTimeout = 50 * time.Millisecond
	// promptTimeout=0 (non-interactive) so the hint is expected, giving this
	// test a positive string to assert on rather than only the absence of a
	// crash.
	k := newHangingKeychainWithPromptTimeout(t, shortTimeout, 0)

	addErr := k.Add("x", "acct", "pw")
	addUnavailable := assertPromptTimeout(t, "Add() against a hanging security binary", addErr)
	if !strings.Contains(addUnavailable.Reason, "not detected as a terminal") {
		t.Errorf("Add() Reason = %q, want the same interactivity hint classifySecurityError gives read/delete", addUnavailable.Reason)
	}

	_, listErr := k.List()
	listUnavailable := assertPromptTimeout(t, "List() against a hanging security binary", listErr)
	if !strings.Contains(listUnavailable.Reason, "not detected as a terminal") {
		t.Errorf("List() Reason = %q, want the same interactivity hint classifySecurityError gives read/delete", listUnavailable.Reason)
	}
}

// TestIsAvailable_UsesTimeoutWhenNotInteractive proves show-keychain-info
// stays on the machine bound (k.timeout) when this Keychain is not
// interactive, regardless of any k.promptTimeout value that happens to be
// set on it — mirroring TestRunSecurityPrompt_ZeroPromptTimeoutFallsBackToTimeout's
// non-interactive case for the other methods.
//
// This used to be TestIsAvailable_IgnoresPromptTimeout, asserting
// show-keychain-info ignores k.promptTimeout unconditionally. That claim
// does not survive measurement (see runSecurity's doc comment: on
// 2026-09-16, show-keychain-info raised a real unlock dialog against a
// locked scratch keychain), and the fix built on it — IsAvailable now takes
// the same interactivity-aware bound as every other call in this file. What
// survives is narrower: a *non-interactive* IsAvailable still stays on the
// machine bound, which is what this test now actually pins, using a
// Keychain built with promptTimeout set but interactive deliberately left
// false — the decoupled case Keychain.interactive's doc comment exists to
// make representable.
func TestIsAvailable_UsesTimeoutWhenNotInteractive(t *testing.T) {
	t.Parallel()
	const (
		shortTimeout = 50 * time.Millisecond
		longPrompt   = 2 * time.Second
	)
	k := newHangingKeychainWithPromptTimeout(t, shortTimeout, longPrompt)
	k.interactive = false // decoupled from promptTimeout, deliberately

	start := time.Now()
	err := k.IsAvailable()
	elapsed := time.Since(start)

	if limit := shortTimeout + 5*securityWaitDelay; elapsed > limit {
		t.Fatalf("IsAvailable() took %s, want it bounded near k.timeout (%s) when not interactive, regardless of k.promptTimeout (%s) (limit %s)",
			elapsed, shortTimeout, longPrompt, limit)
	}
	unavailable := assertPromptTimeout(t, "IsAvailable() against a hanging security binary, not interactive", err)
	if !strings.Contains(unavailable.Reason, "not detected as a terminal") {
		t.Errorf("Reason = %q, want the non-interactive hint since this call was not given a prompt bound", unavailable.Reason)
	}
}

// TestKeychainPromptTimeoutReason_InteractiveOmitsTerminalHint proves the
// converse of TestRunSecurityPrompt_ZeroPromptTimeoutFallsBackToTimeout's
// message assertion: when a prompting call had promptTimeout set (i.e. this
// process did find a terminal on stderr) and still timed out, the message
// says nothing about a missing terminal, because there was not one to
// report missing — humanResponseTimeout already gave a person, if one was
// there, every reasonable chance to answer.
func TestKeychainPromptTimeoutReason_InteractiveOmitsTerminalHint(t *testing.T) {
	t.Parallel()
	const promptBound = 100 * time.Millisecond
	k := newHangingKeychainWithPromptTimeout(t, promptBound, promptBound)

	_, err := k.GetPassword("irrelevant")
	unavailable := assertPromptTimeout(t, "GetPassword() against a hanging security binary with promptTimeout set", err)
	if strings.Contains(unavailable.Reason, "not detected as a terminal") {
		t.Errorf("Reason = %q, want no non-interactive hint: promptTimeout was set, so a terminal was in fact detected", unavailable.Reason)
	}
}

// newDelayedMissThenHangingKeychain returns a *Keychain whose security
// stand-in answers firstSubcommand with a definitive "not found" (exit
// secItemNotFoundExitCode) after missDelay, and hangs forever (sleep 300)
// on any other subcommand.
//
// It exists because newHangingKeychainWithPromptTimeout cannot exercise
// promptOperationContext's actual point: findPassword and Delete only try
// their second subcommand after a *definitive* miss on the first (see each
// method's own comment on why), so a stand-in that hangs on the first call
// too never reaches the second one at all — the shared-vs-fresh-deadline
// distinction is simply never exercised, and TestFindPassword_ and
// TestDelete_SharesOneDeadlineAcrossBothCalls would pass identically
// whether or not the deadline is actually shared. Only a first call that
// completes — after a delay long enough to matter, but as a genuine miss
// rather than a timeout — lets the second call's wait be observed at all,
// and lets a shared deadline (which gives the second call only what the
// first one left behind) be told apart from two independent ones (which
// gives it a full fresh window on top of missDelay).
//
// The first exec of a freshly t.TempDir()-written binary — this function's
// binary, every time it is called, since t.TempDir() is unique per call —
// measured on this environment at up to ~400ms of one-time overhead on top
// of the process's own work (a bare `exit 44` with no sleep at all still
// cost ~280-310ms; a same-path re-exec afterward cost ~10ms), plausibly
// code-signing or Gatekeeper verification rather than anything about exec
// itself. It lands once, on whichever subcommand actually runs first
// (firstSubcommand), not on the second invocation of this same binary
// file. Callers sizing missDelay/promptBound against
// sharedDeadlineMargin need to budget for it on that call alone, not
// double it.
func newDelayedMissThenHangingKeychain(t *testing.T, timeout, promptTimeout, missDelay time.Duration, firstSubcommand string) *Keychain {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "security")
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n\t%s) sleep %.3f; exit %d ;;\n\t*) exec sleep 300 ;;\nesac\n",
		firstSubcommand, missDelay.Seconds(), secItemNotFoundExitCode)
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in security script: %v", err)
	}
	return &Keychain{
		keychainPath:  filepath.Join(dir, "irrelevant.keychain-db"),
		security:      binary,
		timeout:       timeout,
		promptTimeout: promptTimeout,
		// See newHangingKeychainWithPromptTimeout's identical field for why
		// this tracks promptTimeout here.
		interactive: promptTimeout != 0,
	}
}

// sharedDeadlineMarginPercent is the two TestXxx_SharesOneDeadlineAcrossBothCalls
// tests' tolerance around promptBound, expressed as a fraction of the
// window rather than a fixed absolute duration.
//
// This constant replaces sharedDeadlineJitterAllowance (a fixed 1000ms,
// briefly widened to 2000ms by a follow-up commit this one supersedes,
// after a single observed miss at 6.000933671s against a 5s promptBound —
// 0.9ms over the then-6000ms limit — under full-suite t.Parallel()
// contention). Widening a fixed allowance on a multi-second window was
// fixing the symptom: review round 2 measured 3 failures in ~1800
// sub-test executions of these two tests, all landing within a few
// milliseconds of the ceiling, and pointed out the window itself
// (missDelay 3000ms, promptBound 5000ms) was unnecessarily large for the
// "was this call actually bounded by the prompt timeout" question —
// TestRunSecurityPrompt_AllPromptingCallSitesUsePromptTimeout already
// answers a version of it at promptBound=300ms — and was also the
// backend package's test-suite cost driver (~9.3s on main to 11-12.5s).
// Shrinking the window (missDelay, promptBound below) is the actual fix;
// expressing the margin as a fraction of it, rather than a value picked to
// fit one measurement on one machine, is what keeps that fix from being
// silently undone the next time either constant changes: a fixed
// millisecond figure that was barely enough at 5-6s is far too much at a
// few hundred milliseconds, and one derived from nothing would be too
// little at a much larger window some future change might need.
const sharedDeadlineMarginPercent = 20

// sharedDeadlineMargin returns sharedDeadlineMarginPercent of window,
// rounded to the nearest millisecond for readable failure messages.
func sharedDeadlineMargin(window time.Duration) time.Duration {
	return (window * sharedDeadlineMarginPercent / 100).Round(time.Millisecond)
}

// TestFindPassword_SharesOneDeadlineAcrossBothCalls proves
// promptOperationContext's actual point for findPassword: the
// generic-then-internet attempts share one deadline instead of each
// getting their own — checked from both directions.
//
// A shared deadline totals ~promptBound, independent of the missDelay/tax
// split within it: ctx's deadline is absolute from the moment
// promptOperationContext is called, so once the first (missed) call
// returns, the second (hanging) call gets whatever of promptBound is left
// and is killed when the shared deadline arrives, regardless of how much
// of it the first call used. Two failure shapes on either side of that
// total are what the lower and upper bounds each catch:
//
//   - Too fast (below the lower bound): the second call reverted to an
//     independent short bound (e.g. k.timeout) instead of sharing ctx —
//     round 2's "silently revertible with CI green" finding, which an
//     upper-bound-only assertion cannot see at all, because a call that
//     returns early never risks exceeding an upper bound.
//   - Too slow (above the upper bound): the second call reverted to an
//     independent *fresh* runSecurity-style deadline instead of sharing
//     ctx, taking ~missDelay+promptBound instead of ~promptBound.
//
// missDelay is sized to separate the "too fast" and "too slow" totals from
// the correct one by more than sharedDeadlineMargin(promptBound) even in
// the worst case measured for this environment's one-time
// per-fresh-executable startup cost (up to ~400ms, see
// newDelayedMissThenHangingKeychain's doc comment) landing entirely on one
// side or the other; promptBound is sized to comfortably exceed
// missDelay plus that same worst case, so the first call always completes
// on its own before the shared deadline could fire mid-sleep and trigger
// the unrelated grandchild/WaitDelay wait TestRunSecurity_
// WaitDelayBoundsGrandchildHoldingPipe covers.
//
// Deliberately not t.Parallel(), for the same reason
// TestRunSecurityBounded_TimeoutIncludesChildStderr gives: a context's
// deadline is wall-clock, absolute, and set before the process it bounds
// has necessarily started, so heavy CPU contention from sibling tests
// forking their own stand-in processes at the same time can delay actual
// process start long enough to eat into that budget before the process
// does any observable work — measured directly here: under full-suite
// `-count=1` contention this test's own mutation-verification run (revert
// the internet-password leg to an independent runSecurity call, expected
// ~1.3-1.8s) landed anywhere from 1.00s (indistinguishable from the
// correct, shared-deadline case) to 1.72s (correctly over the ceiling)
// across three consecutive full-suite runs. Isolated (`-run`, no sibling
// contention) it failed reliably every time. Running serially removes that
// contention the same way it did for the sibling test.
func TestFindPassword_SharesOneDeadlineAcrossBothCalls(t *testing.T) {
	const (
		shortTimeout = 20 * time.Millisecond
		missDelay    = 300 * time.Millisecond
		promptBound  = 1000 * time.Millisecond
	)
	k := newDelayedMissThenHangingKeychain(t, shortTimeout, promptBound, missDelay, "find-generic-password")

	start := time.Now()
	_, err := k.GetPassword("irrelevant")
	elapsed := time.Since(start)

	margin := sharedDeadlineMargin(promptBound)
	if lower := promptBound - margin; elapsed < lower {
		t.Errorf("GetPassword() took %s, want at least %s: a second call that returns before the shared deadline reverted to its own independent (and shorter) bound instead of sharing promptOperationContext's",
			elapsed, lower)
	}
	if upper := promptBound + margin; elapsed > upper {
		t.Errorf("GetPassword() took %s, want it bounded near promptBound (%s, limit %s): the generic and internet attempts must share one deadline, not each get their own (independent deadlines would total ~%s)",
			elapsed, promptBound, upper, missDelay+promptBound)
	}
	assertPromptTimeout(t, "GetPassword() against a delayed-miss-then-hanging security binary", err)
}

// TestDelete_SharesOneDeadlineAcrossBothCalls is
// TestFindPassword_SharesOneDeadlineAcrossBothCalls's counterpart for
// Delete, which shares its own promptOperationContext deadline across
// delete-generic-password and delete-internet-password. It is not
// redundant with the findPassword test: Delete calls
// runSecurityBoundedCtx directly rather than through findPassword, so a
// regression here (e.g. Delete's second call reverting to an independent
// deadline) would not be caught by the findPassword test alone. See that
// test's doc comment for the full reasoning behind the constants and
// bounds, shared verbatim here — including why this is deliberately not
// t.Parallel() either.
func TestDelete_SharesOneDeadlineAcrossBothCalls(t *testing.T) {
	const (
		shortTimeout = 20 * time.Millisecond
		missDelay    = 300 * time.Millisecond
		promptBound  = 1000 * time.Millisecond
	)
	k := newDelayedMissThenHangingKeychain(t, shortTimeout, promptBound, missDelay, "delete-generic-password")

	start := time.Now()
	err := k.Delete("irrelevant")
	elapsed := time.Since(start)

	margin := sharedDeadlineMargin(promptBound)
	if lower := promptBound - margin; elapsed < lower {
		t.Errorf("Delete() took %s, want at least %s: a second call that returns before the shared deadline reverted to its own independent (and shorter) bound instead of sharing promptOperationContext's",
			elapsed, lower)
	}
	if upper := promptBound + margin; elapsed > upper {
		t.Errorf("Delete() took %s, want it bounded near promptBound (%s, limit %s): the generic and internet attempts must share one deadline, not each get their own (independent deadlines would total ~%s)",
			elapsed, promptBound, upper, missDelay+promptBound)
	}
	assertPromptTimeout(t, "Delete() against a delayed-miss-then-hanging security binary", err)
}

// openTestPTY opens a fresh macOS pseudo-terminal pair via /dev/ptmx and the
// TIOCPTY* ioctls — the same mechanism github.com/creack/pty uses on
// darwin, reimplemented here without adding it as a dependency (it is not a
// direct dependency of this module, and this repo takes no new ones for one
// test). It exists so TestIsTerminal_PTYIsATerminal can prove isTerminal
// answers true for an actual terminal device, not only false for
// /dev/null (TestIsTerminal_DevNullIsNotATerminal): a mutation that
// hard-wires isTerminal, or isInteractive above it, to return false makes
// every other test in this file pass, because none of the rest runs with a
// real terminal on the fd being probed (review round 1 on #68).
//
// Returns the slave end open for read/write; t.Cleanup handles closing both
// ends. Skips, rather than fails, if /dev/ptmx cannot be opened or granted:
// a sandboxed environment has been seen to deny pty allocation outright,
// which is an environment limitation, not a regression in the code under
// test.
func openTestPTY(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })

	if err := ptyIoctl(master.Fd(), unix.TIOCPTYGRANT, 0); err != nil {
		t.Skipf("ioctl TIOCPTYGRANT: %v", err)
	}
	if err := ptyIoctl(master.Fd(), unix.TIOCPTYUNLK, 0); err != nil {
		t.Skipf("ioctl TIOCPTYUNLK: %v", err)
	}

	// TIOCPTYGNAME's encoded parameter length (bits 16-28 of the ioctl
	// request number, per the _IOC_PARM_LEN convention BSD-derived ioctls
	// use) is 128 bytes; taken from github.com/creack/pty's darwin
	// implementation, which this helper otherwise mirrors, rather than
	// derived from Apple documentation (there is none for this ioctl).
	const ptyGNameLen = 128
	name := make([]byte, ptyGNameLen)
	if err := ptyIoctl(master.Fd(), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); err != nil {
		t.Skipf("ioctl TIOCPTYGNAME: %v", err)
	}
	nul := bytes.IndexByte(name, 0)
	if nul < 0 {
		t.Fatalf("TIOCPTYGNAME response not NUL-terminated: %q", name)
	}

	slave, err := os.OpenFile(string(name[:nul]), os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open pty slave %s: %v", name[:nul], err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return slave
}

// ptyIoctl issues a raw ioctl via the syscall golang.org/x/sys/unix already
// exposes generic access to (unix.Syscall/unix.SYS_IOCTL), for the three
// TIOCPTY* requests openTestPTY needs: none of them fit the fixed
// int/Termios/Winsize shapes unix.IoctlSet*/IoctlGet* already wrap.
func ptyIoctl(fd uintptr, req uint, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(req), arg)
	if errno != 0 {
		return errno
	}
	return nil
}

// TestIsTerminal_DevNullIsNotATerminal is the mutant this test exists to
// kill named directly: an os.Stat/ModeCharDevice check would call this
// interactive, because /dev/null is a character device — exactly the
// mistake isTerminal's doc comment says IoctlGetTermios avoids.
func TestIsTerminal_DevNullIsNotATerminal(t *testing.T) {
	t.Parallel()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer f.Close()
	if isTerminal(f.Fd()) {
		t.Error("isTerminal(/dev/null) = true, want false")
	}
}

// TestIsTerminal_PTYIsATerminal is TestIsTerminal_DevNullIsNotATerminal's
// positive counterpart: without it, isTerminal hard-wired to unconditionally
// return false passes every other test in this file, because none of them
// runs with a real terminal on the fd being probed.
func TestIsTerminal_PTYIsATerminal(t *testing.T) {
	t.Parallel()
	slave := openTestPTY(t)
	if !isTerminal(slave.Fd()) {
		t.Error("isTerminal(pty slave) = false, want true: a pty slave is an actual terminal device")
	}
}

// TestIsInteractive_ReflectsStderr proves isInteractive is actually wired to
// probe os.Stderr, not merely that isTerminal (which the two tests above
// pin) is correct in isolation. Without this, isInteractive's one-line body
// could be mutated to ignore isTerminal entirely — hard-wired to
// unconditionally return false, silently disabling all of #67 — and
// nothing in this file would notice: no other test here calls isInteractive
// itself, precisely because newKeychain takes the interactivity decision as
// an injected parameter so that everything else can avoid touching the
// process's real stderr (see TestNewKeychain_PromptTimeout).
//
// This is the one test in the package that deliberately does touch it, by
// reassigning os.Stderr to a pty slave (open, interactive) and then to
// /dev/null (open, non-interactive) in turn, restoring it immediately after
// via defer. It is deliberately not t.Parallel(): reassigning a
// process-global var that other code may write diagnostics through is not
// something to do while a sibling test could be running too — the same
// reasoning TestRunSecurityBounded_TimeoutIncludesChildStderr's own
// non-parallel comment gives for a different shared resource. Go's testing
// package guarantees paused (t.Parallel()) tests do not execute while a
// serial test's body is running, so this does not race with them.
func TestIsInteractive_ReflectsStderr(t *testing.T) {
	original := os.Stderr
	defer func() { os.Stderr = original }()

	slave := openTestPTY(t)
	os.Stderr = slave
	if !isInteractive() {
		t.Error("isInteractive() = false with os.Stderr pointed at a pty, want true")
	}

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer null.Close()
	os.Stderr = null
	if isInteractive() {
		t.Error("isInteractive() = true with os.Stderr pointed at /dev/null, want false")
	}
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

// TestSecurityBoundsRespectCap pins the /usr/bin/security bounds under the
// hard ceiling from timeouts.go.
//
// The two are summed rather than checked separately because that is how they
// compose in runSecurity: on a timeout it kills the process and then waits up
// to securityWaitDelay for the inherited pipes to close, so the worst case a
// caller can observe is the sum. Checking them individually would let the pair
// drift back over the cap while each half still looked compliant.
//
// Keychain.promptTimeout is deliberately not checked here, mirroring how
// TestDbusCallTimeoutRespectsCap (libsecret_test.go) exempts
// promptWaitTimeout: when set, promptTimeout holds humanResponseTimeout,
// which bounds a wait on a person rather than on the security process, and
// timeouts.go excludes exactly that from maxExternalCallTimeout. Asserting
// it here would encode the opposite rule; see
// TestHumanResponseTimeoutExceedsExternalCallTimeout (timeouts_test.go) for
// the check that does apply to it.
func TestSecurityBoundsRespectCap(t *testing.T) {
	t.Parallel()
	if worst := securityCommandTimeout + securityWaitDelay; worst > maxExternalCallTimeout {
		t.Errorf("securityCommandTimeout (%s) + securityWaitDelay (%s) = %s, exceeds maxExternalCallTimeout (%s)",
			securityCommandTimeout, securityWaitDelay, worst, maxExternalCallTimeout)
	}
}
