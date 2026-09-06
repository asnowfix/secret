//go:build darwin

package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// securityBinary is the path to the real Apple security CLI. It is a const:
// the test seam is the per-Keychain security field, so that nothing in this
// package mutates global state (and tests can therefore run in parallel).
const securityBinary = "/usr/bin/security"

// securityCommandTimeout bounds every call to the security CLI. This path is
// meant to be entirely non-interactive, but /usr/bin/security itself does
// not honor that on its own: against a locked keychain it can hand off to
// the system's interactive keychain-unlock UI, and on a headless session
// (e.g. a CI runner with no logged-in GUI user to answer that prompt) that
// hand-off blocks forever with no output. This was confirmed to not be a
// case of Go's exec.Cmd inheriting/blocking on stdin — cmd.Stdin is left nil
// throughout this file, and a nil Stdin has made the child read from
// os.DevNull (immediate EOF) rather than from the parent's terminal since
// Go 1.0 — so the fix has to bound the call itself, not stdin. (What Go 1.20
// added, and what runSecurity uses, is Cmd.Cancel/Cmd.WaitDelay.)
const securityCommandTimeout = 10 * time.Second

// securityWaitDelay is how long runSecurity waits, after killing a timed-out
// security process, for its inherited stdout/stderr pipes to close before
// giving up on them. Without it the timeout is not a hard bound: cmd.Wait
// blocks until the pipes reach EOF, and killing the direct child does not
// close pipes still held open by any grandchild it left behind.
const securityWaitDelay = time.Second

// errSecurityTimeout is runSecurity's sentinel for "the security process did
// not finish within the configured timeout". It must never be treated as
// errItemNotFound: an unresponsive keychain is not a confirmed absence, and
// collapsing the two would recreate the exact silent-overwrite bug (issue
// #30) this file's error classification exists to prevent.
var errSecurityTimeout = errors.New("security command did not respond within the timeout")

// Keychain implements Backend using the macOS /usr/bin/security CLI.
type Keychain struct {
	keychainPath string
	// security is the path to the security CLI, and timeout bounds every
	// invocation of it. They are fields rather than package vars so tests can
	// substitute a stand-in binary and a short timeout without mutating
	// process-wide state.
	security string
	timeout  time.Duration
}

func NewKeychain() *Keychain {
	home, _ := os.UserHomeDir()
	return &Keychain{
		keychainPath: filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		security:     securityBinary,
		timeout:      securityCommandTimeout,
	}
}

func (k *Keychain) IsAvailable() error {
	if _, err := k.runSecurity("show-keychain-info", k.keychainPath); err != nil {
		return &ErrUnavailable{Reason: keychainUnavailableReason(k.keychainPath, err)}
	}
	return nil
}

// keychainUnavailableReason describes why show-keychain-info failed instead
// of asserting the single most likely cause. IsAvailable runs from the root
// command's PersistentPreRunE before every subcommand, which makes this the
// most-seen error message in the product; it used to report "keychain
// locked" for a missing keychain file, a missing security binary, a timeout
// and a permissions failure alike.
//
// The cause comes first and the remedy second: a locked keychain is the most
// common reason this fails, and it is worth suggesting the fix for, but it is
// a suggestion phrased as one rather than a claim that stays wrong for every
// other cause.
func keychainUnavailableReason(path string, err error) string {
	if errors.Is(err, errSecurityTimeout) {
		return keychainTimeoutReason(err)
	}
	return fmt.Sprintf("could not open keychain %s: %v — if it is locked, run `security unlock-keychain %s`", path, err, path)
}

var acctRegexp = regexp.MustCompile(`^\s+"acct"<[^>]*>=(?:"([^"]*)"|0x([0-9A-Fa-f]+))`)

// svceRegexp matches the "svce" (generic password) or "srvr" (internet password)
// attribute lines emitted by `security dump-keychain`.
var svceRegexp = regexp.MustCompile(`^\s+"(?:svce|srvr)"<[^>]*>=(?:"([^"]*)"|0x([0-9A-Fa-f]+))`)

func (k *Keychain) GetUsername(service string) (string, error) {
	output, err := k.findPassword(service, false)
	if err != nil {
		return "", classifySecurityError(service, "read", err)
	}
	account, err := parseAccount(output)
	if err != nil {
		return "", &ErrUnavailable{Reason: fmt.Sprintf("could not read keychain item for %q: %v", service, err)}
	}
	return account, nil
}

// parseAccount extracts the "acct" attribute from the attribute dump
// `security find-generic-password -g` writes to stdout.
//
// A lookup that succeeded but whose output has no usable acct line is a
// parse failure, not an absence. Reporting it as *ErrNotFound would be issue
// #30's bug in miniature: telling the caller the credential is not there
// when in fact we merely could not read its account name — and cmd/set.go
// treats *ErrNotFound as "safe to overwrite".
func parseAccount(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		m := acctRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[1] != "" {
			return m[1], nil
		}
		if m[2] == "" {
			continue
		}
		decoded, err := hexDecode(m[2])
		if err != nil {
			return "", fmt.Errorf("malformed hex-encoded \"acct\" attribute: %w", err)
		}
		return decoded, nil
	}
	return "", errors.New(`no "acct" attribute in security output`)
}

func (k *Keychain) GetPassword(service string) (string, error) {
	output, err := k.findPassword(service, true)
	if err != nil {
		return "", classifySecurityError(service, "read", err)
	}
	return strings.TrimRight(output, "\n"), nil
}

// classifySecurityError maps an error from runSecurity onto the Backend
// error types callers switch on, mirroring classifyBusError (libsecret.go)
// and classifyCredError (wincred.go). Only the definitive errItemNotFound
// sentinel becomes *ErrNotFound; everything else — a timeout, a locked
// keychain, a missing binary, an unexpected exit code — becomes
// *ErrUnavailable, so "could not tell" is never reported as "not there".
//
// op names the operation for the diagnostic ("read", "delete"); it does not
// affect the returned type.
func classifySecurityError(service, op string, err error) error {
	switch {
	case errors.Is(err, errItemNotFound):
		return &ErrNotFound{Service: service}
	case errors.Is(err, errSecurityTimeout):
		return &ErrUnavailable{Reason: keychainTimeoutReason(err)}
	default:
		return &ErrUnavailable{Reason: fmt.Sprintf("could not %s keychain item for %q: %v", op, service, err)}
	}
}

// keychainTimeoutReason builds the *ErrUnavailable diagnostic for a security
// invocation that timed out, naming the likely cause (a locked keychain with
// no agent able to answer an unlock prompt) rather than a generic failure.
func keychainTimeoutReason(err error) string {
	return fmt.Sprintf("keychain unavailable: %v — it may be locked with no agent able to answer an unlock prompt", err)
}

func (k *Keychain) Add(service, account, password string) error {
	// -T names the real Apple binary deliberately, not k.security: the
	// non-interactive ACL grant it creates is the entire reason this backend
	// shells out to /usr/bin/security instead of using cgo (see AGENTS.md),
	// so it must never follow the test seam.
	_, err := k.runSecurity("add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", securityBinary,
		k.keychainPath,
	)
	if err != nil {
		// Deliberately not classifySecurityError: a write has no meaningful
		// "not found" outcome, so every failure here is *ErrUnavailable.
		return &ErrUnavailable{Reason: fmt.Sprintf("failed to add secret for '%s': %v", service, err)}
	}
	return nil
}

func (k *Keychain) Delete(service string) error {
	// Same discipline as findPassword, and for the same reason. Only a
	// definitive "no such item" in the generic-password class justifies
	// trying the internet-password class, and only a definitive "no such
	// item" from both is *ErrNotFound. Anything else means we cannot tell
	// whether anything was deleted, and must not be reported as "there was
	// nothing to delete": cmd/gitcredential.go's store and erase paths
	// suppress *ErrNotFound from Delete entirely, so collapsing here makes
	// `git credential reject` against a locked keychain report success having
	// deleted nothing (issue #36; same bug class as #30).
	_, err := k.runSecurity("delete-generic-password", "-s", service, k.keychainPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errItemNotFound) {
		return classifySecurityError(service, "delete", err)
	}

	if _, err := k.runSecurity("delete-internet-password", "-s", service, k.keychainPath); err != nil {
		return classifySecurityError(service, "delete", err)
	}
	return nil
}

func (k *Keychain) Edit() error {
	cmd := exec.Command("open", "-b", "com.apple.keychainaccess")
	if err := cmd.Start(); err != nil {
		return err
	}
	// `open` returns as soon as LaunchServices has taken over, so reaping it
	// costs nothing and keeps the finished child from lingering as a zombie
	// for the rest of the process's life.
	go func() { _ = cmd.Wait() }()
	return nil
}

func (k *Keychain) List() ([]string, error) {
	out, err := k.runSecurity("dump-keychain", k.keychainPath)
	if err != nil {
		return nil, &ErrUnavailable{Reason: fmt.Sprintf("failed to list secrets: %v", err)}
	}
	return parseKeychainDumpServices(out), nil
}

// parseKeychainDumpServices extracts the deduplicated, sorted set of service
// names from `security dump-keychain` output, matching "svce" (generic
// password) and "srvr" (internet password) attribute lines.
func parseKeychainDumpServices(dump string) []string {
	var names []string
	for _, line := range strings.Split(dump, "\n") {
		m := svceRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		var name string
		switch {
		case m[1] != "":
			name = m[1]
		case m[2] != "":
			decoded, err := hexDecode(m[2])
			if err != nil {
				continue
			}
			name = decoded
		default:
			continue
		}

		names = append(names, name)
	}
	return DedupeSortServices(names)
}

// errItemNotFound is runSecurity's internal sentinel for a definitive "no
// such item". Any other failure (locked keychain, missing binary, unexpected
// exit code) is returned as its own error instead, so callers can tell
// "absent" apart from "could not determine" rather than collapsing both into
// *ErrNotFound.
var errItemNotFound = errors.New("keychain item not found")

// secItemNotFoundExitCode is the Unix exit code /usr/bin/security uses to
// report errSecItemNotFound (OSStatus -25300). An OSStatus becomes a process
// exit code via its low byte (-25300 & 0xFF == 44); verified by hand against
// a scratch keychain (see PR #31) rather than assumed.
const secItemNotFoundExitCode = 44

// itemNotFoundMessage is the diagnostic /usr/bin/security prints for
// errSecItemNotFound. It corroborates secItemNotFoundExitCode: either signal
// on its own is enough to classify a definitive absence.
//
// Two independent signals rather than one, and OR rather than AND, because
// the two failure modes are not symmetric. If 44 stopped being the code on
// some future macOS or security build, requiring it alone would turn every
// genuine miss into *ErrUnavailable — `secret set` would then refuse every
// write, and the generic→internet fallback would stop entirely. Requiring
// both signals would have the same effect the first time Apple reworded the
// message. Accepting either degrades gracefully instead.
const itemNotFoundMessage = "could not be found in the keychain"

// securityLockedExitCode is the exit code observed from /usr/bin/security
// when it is asked to read a locked keychain that *does* hold the item.
// Measured against the real binary on macOS: exit 152 with completely empty
// stderr. (A locked keychain that does not hold the item exits 44 instead —
// so a locked keychain is indistinguishable from a genuine miss for an item
// that was never there. That collision is inherent to the CLI and is not
// something this layer can resolve.)
//
// Unlike 44 this code is not derivable: it maps to no documented errSec*
// value under the low-byte rule (errSecInteractionNotAllowed -25308 would be
// 36, errSecAuthFailed -25293 would be 51). It is recorded here as an
// observation, used only to add a hint to a diagnostic and never to classify
// an error type.
const securityLockedExitCode = 152

// securityPasswordLine matches the `password: "..."` line `security
// find-generic-password -g` writes to stderr. Failure diagnostics interpolate
// stderr, and cmd/gitcredential.go documents that no error path from this
// package can carry a password value; redacting the line keeps that true even
// if security ever printed a secret alongside a non-zero exit.
var securityPasswordLine = regexp.MustCompile(`(?m)^password: ".*"$`)

// runSecurity runs the security CLI with the given arguments, bounded by
// k.timeout, and classifies the result: success returns stdout; a definitive
// "item not found" returns errItemNotFound; a timeout returns
// errSecurityTimeout; anything else (locked keychain, missing/non-executable
// binary, unexpected exit code) returns an error carrying whatever diagnostic
// security produced — plus the exit code itself, which is otherwise invisible
// to the user and is the only handle on an unmodelled failure.
//
// The child is bounded via exec.CommandContext rather than a bare
// exec.Command: on timeout the context's default Cancel kills the child, and
// WaitDelay then bounds how long Wait will keep waiting on the stdout/stderr
// pipes afterwards. Without WaitDelay the kill is not a hard bound, because
// Stdout/Stderr are buffers rather than *os.File and Wait blocks until the
// pipes reach EOF — which a grandchild holding them open would prevent.
// cmd.Stdin is left nil, i.e. /dev/null, so the child can never block reading
// from an inherited terminal either.
func (k *Keychain) runSecurity(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, k.security, args...)
	cmd.WaitDelay = securityWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%w (security %s, timeout %s)", errSecurityTimeout, args[0], k.timeout)
		}
		msg := redactPasswords(strings.TrimSpace(stderr.String()))
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if exitCode == secItemNotFoundExitCode || strings.Contains(msg, itemNotFoundMessage) {
			return "", errItemNotFound
		}
		return "", fmt.Errorf("security %s: %s", args[0], securityFailureDetail(exitCode, msg, err))
	}
	return stdout.String(), nil
}

// securityFailureDetail renders the diagnostic for a security invocation that
// failed for a reason other than a timeout or a definitive miss.
//
// The exit code is always named. It is the only handle on a failure this file
// does not model, and it was previously invisible to the user — the empty
// stderr case is not defensive padding but the single most important
// real-world failure, measured: a locked keychain holding the requested item
// exits 152 and prints nothing at all.
func securityFailureDetail(exitCode int, stderrMsg string, runErr error) string {
	if exitCode < 0 {
		// Not an *exec.ExitError at all: the process never ran (missing or
		// non-executable binary, or it was signalled). runErr is the only
		// diagnostic there is.
		if stderrMsg != "" {
			return fmt.Sprintf("%v: %s", runErr, stderrMsg)
		}
		return runErr.Error()
	}
	detail := fmt.Sprintf("exit status %d", exitCode)
	if exitCode == securityLockedExitCode {
		detail += " (keychain appears locked; try `security unlock-keychain`)"
	}
	if stderrMsg != "" {
		detail += ": " + stderrMsg
	}
	return detail
}

// redactPasswords replaces the value on any `password: "..."` line so that a
// secret cannot reach an error string.
func redactPasswords(s string) string {
	return securityPasswordLine.ReplaceAllString(s, `password: "<redacted>"`)
}

func (k *Keychain) findPassword(service string, passwordOnly bool) (string, error) {
	var flag string
	if passwordOnly {
		flag = "-w"
	} else {
		flag = "-g"
	}

	// Try generic password first. A real failure here (not a "not found")
	// means we cannot determine whether the item exists at all, so return
	// immediately rather than masking it with an internet-password attempt.
	out, err := k.runSecurity("find-generic-password", flag, "-s", service, k.keychainPath)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, errItemNotFound) {
		return "", err
	}

	// Fall back to internet password.
	return k.runSecurity("find-internet-password", flag, "-s", service, k.keychainPath)
}

func hexDecode(s string) (string, error) {
	// Guard the loop below, which reads s in pairs and would index past the
	// end of an odd-length string. `security` never emits one, but the value
	// comes from parsing its output, and a panic is a poor way to find out.
	if len(s)%2 != 0 {
		return "", fmt.Errorf("odd-length hex string: %q", s)
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				val = val*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				val = val*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val = val*16 + (c - 'A' + 10)
			default:
				return "", fmt.Errorf("invalid hex char: %c", c)
			}
		}
		b[i/2] = val
	}
	return string(b), nil
}
