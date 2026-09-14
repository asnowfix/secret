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

	"golang.org/x/sys/unix"
)

// securityBinary is the path to the real Apple security CLI. It is a const:
// the test seam is the per-Keychain security field, so that nothing in this
// package mutates global state (and tests can therefore run in parallel).
const securityBinary = "/usr/bin/security"

// securityCommandTimeout is the machine bound applied to every security CLI
// invocation that cannot raise a dialog — currently only show-keychain-info,
// via runSecurity/IsAvailable — and is also runSecurityPrompt's fallback for
// a prompting call made when this process found no terminal on stderr. This
// path is meant to be entirely non-interactive, but /usr/bin/security itself
// does not honor that on its own: against a locked keychain it can hand off
// to the system's interactive keychain-unlock UI, and on a headless session
// (e.g. a CI runner with no logged-in GUI user to answer that prompt) that
// hand-off blocks forever with no output. This was confirmed to not be a
// case of Go's exec.Cmd inheriting/blocking on stdin — cmd.Stdin is left nil
// throughout this file, and a nil Stdin has made the child read from
// os.DevNull (immediate EOF) rather than from the parent's terminal since
// Go 1.0 — so the fix has to bound the call itself, not stdin. (What Go 1.20
// added, and what runSecurityBoundedCtx uses, is Cmd.Cancel/Cmd.WaitDelay.)
//
// The value comes from externalCallTimeout (timeouts.go), which carries the
// measurements it was derived from and the reasoning for the floor applied
// to them. Note the effective worst case for any one security invocation
// bounded by this constant is this plus securityWaitDelay below; both
// together must stay under maxExternalCallTimeout, which
// TestSecurityBoundsRespectCap asserts. A prompting call bounded instead by
// Keychain.promptTimeout (i.e. humanResponseTimeout, timeouts.go) is
// deliberately exempt from that cap — see promptTimeout's doc comment and
// TestSecurityBoundsRespectCap's.
const securityCommandTimeout = externalCallTimeout

// securityWaitDelay is how long runSecurityBoundedCtx waits, after killing a
// timed-out security process, for its inherited stdout/stderr pipes to close
// before giving up on them. Without it the timeout is not a hard bound:
// cmd.Wait blocks until the pipes reach EOF, and killing the direct child
// does not close pipes still held open by any grandchild it left behind.
const securityWaitDelay = time.Second

// isTerminal reports whether fd refers to a terminal, via
// unix.IoctlGetTermios(TIOCGETA) rather than an os.Stat/ModeCharDevice
// check: /dev/null is a character device, so that check would call a cron
// job with stderr redirected to /dev/null interactive, exactly the case
// this probe exists to exclude. IoctlGetTermios(TIOCGETA) succeeds only for
// an actual tty; TestIsTerminal_DevNullIsNotATerminal and
// TestIsTerminal_PTYIsATerminal pin both directions against real devices
// rather than only against each other.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	return err == nil
}

// isInteractive reports whether this process can plausibly show something a
// person is watching for right now, which is the precondition for deciding
// that a security invocation should be given humanResponseTimeout
// (timeouts.go) instead of securityCommandTimeout: there is no point
// waiting up to that long for someone to answer a dialog if nobody is
// positioned to see it was raised.
//
// It probes stderr, not stdin or stdout, and deliberately: this tool is
// used as a git credential helper, where stdin and stdout are the pipes git
// itself reads and writes as part of the credential protocol, so both are
// pipes even when a human is sitting right at the terminal running `git
// push`. stderr is not part of that protocol — it is the stream this tool
// already uses elsewhere to talk to a human directly (cmd's
// validateBackendEnvIgnoredByFlag warning, and every diagnostic
// cmd/gitcredential.go writes via its stderr parameter) — and it is the one
// stream that stays a terminal through `secret password foo | pbcopy` or a
// credential-helper invocation, and stays redirected through a cron job or
// a CI step that did not attach one.
//
// isInteractive is a plain func, not a mutable package var: the test seam
// for NewKeychain's wiring is newKeychain, which takes the interactivity
// decision as a parameter, following securityBinary's comment above on why
// nothing in this package mutates global state. See
// TestNewKeychain_PromptTimeout, which calls newKeychain directly with a
// fixed answer instead of swapping this function out from under it.
func isInteractive() bool {
	return isTerminal(os.Stderr.Fd())
}

// errSecurityTimeout is runSecurityBoundedCtx's sentinel for "the security
// process did not finish within the configured timeout". It must never be
// treated as errItemNotFound: an unresponsive keychain is not a confirmed
// absence, and collapsing the two would recreate the exact silent-overwrite
// bug (issue #30) this file's error classification exists to prevent.
var errSecurityTimeout = errors.New("security command did not respond within the timeout")

// securityTimeoutError is runSecurityBoundedCtx's concrete error for an
// invocation that hit its deadline. It wraps errSecurityTimeout (via
// Unwrap, so every existing errors.Is(err, errSecurityTimeout) check keeps
// working unchanged) and additionally records prompting: whether the call
// that timed out was made through a security-CLI subcommand that can raise
// a dialog, with an actual non-zero prompt bound in effect at the moment of
// that call.
//
// prompting is captured here, at the call that produced the error, rather
// than re-derived afterward by a caller inspecting Keychain.promptTimeout.
// The two used to be the same computation done twice, which meant a
// diagnostic could describe a call that timed out using field state read
// from whatever *Keychain happened to be in scope when the message was
// built — usually the same value, but not guaranteed to be, and already
// wrong in one place in this file's own tests: the opt-in live-test helper
// newScratchKeychain builds a *Keychain with promptTimeout left at its zero
// value, not because isInteractive() was probed and found nothing, but
// because the helper never sets the field at all. Reading the fact off the
// error it actually produced removes the gap between "what this call was
// bounded by" and "what some *Keychain's field says now" instead of merely
// relocating it.
type securityTimeoutError struct {
	err       error
	prompting bool
}

func (e *securityTimeoutError) Error() string { return e.err.Error() }
func (e *securityTimeoutError) Unwrap() error { return e.err }

// wasPrompting reports whether err is a security timeout that was made
// through a prompting call with a non-zero prompt bound actually in effect,
// as recorded by runSecurityBoundedCtx on the securityTimeoutError itself.
// It returns false for any err that is not a *securityTimeoutError,
// including one built by hand (there are none in production code, but
// nothing stops a future one) and including errSecurityTimeout compared
// directly rather than through this type.
func wasPrompting(err error) bool {
	var timeoutErr *securityTimeoutError
	return errors.As(err, &timeoutErr) && timeoutErr.prompting
}

// Keychain implements Backend using the macOS /usr/bin/security CLI.
type Keychain struct {
	keychainPath string
	// security is the path to the security CLI, and timeout bounds every
	// invocation of it that cannot raise a dialog (and is the fallback for
	// one that can, when promptTimeout is zero). They are fields rather than
	// package vars so tests can substitute a stand-in binary and a short
	// timeout without mutating process-wide state.
	security string
	timeout  time.Duration
	// promptTimeout bounds the calls that can raise a keychain-unlock or
	// per-item access-control dialog (everything runSecurityPrompt,
	// findPassword and Delete are used for; see runSecurityPrompt's doc
	// comment for the exact subcommand list), in place of timeout. Zero
	// means "same as timeout": that keeps every existing &Keychain{...}
	// literal in this file's tests, which do not set it, byte-for-byte
	// identical to the pre-#67 non-interactive behaviour, and keeps
	// newKeychain's own zero value (when the injected interactive func
	// returns false) correct without a separate branch.
	//
	// newKeychain sets this to humanResponseTimeout when interactive()
	// reports a person is plausibly watching stderr; otherwise it leaves it
	// zero, and a prompting call falls back to timeout, exactly as a
	// non-prompting one always has.
	promptTimeout time.Duration
}

func NewKeychain() *Keychain {
	return newKeychain(isInteractive)
}

// newKeychain is NewKeychain with the interactivity decision injected as a
// parameter instead of read from isInteractive directly, so
// TestNewKeychain_PromptTimeout can pin the wiring between "interactive"
// and Keychain.promptTimeout with a fixed answer — never a real terminal,
// never the absence of one — without touching any mutable package state.
// securityBinary's comment above explains why that matters: it is the same
// reason this package's test seams are struct fields and function
// parameters rather than package vars.
func newKeychain(interactive func() bool) *Keychain {
	home, _ := os.UserHomeDir()
	k := &Keychain{
		keychainPath: filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		security:     securityBinary,
		timeout:      securityCommandTimeout,
	}
	if interactive() {
		k.promptTimeout = humanResponseTimeout
	}
	return k
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

// attributeRegexp builds a matcher for the attribute lines `security` writes
// for a keychain item — `    "acct"<blob>="alice"`, or the `0x<hex>` form it
// uses for a value it cannot render as plain text. names is an alternation of
// the attribute names to match.
//
// The two parsers below share this (and parseAttribute) deliberately: they
// had drifted apart once already, with issue #36's dropped hexDecode error
// fixed in parseAccount and left standing in parseKeychainDumpServices.
func attributeRegexp(names string) *regexp.Regexp {
	return regexp.MustCompile(`^\s+"(?:` + names + `)"<[^>]*>=(?:"([^"]*)"|0x([0-9A-Fa-f]+))`)
}

var acctRegexp = attributeRegexp("acct")

// svceRegexp matches the "svce" (generic password) or "srvr" (internet password)
// attribute lines emitted by `security dump-keychain`.
var svceRegexp = attributeRegexp("svce|srvr")

// parseAttribute returns the value of the attribute on line, decoding the
// `0x<hex>` rendering if that is the form used. ok reports whether line is an
// attribute line at all; err is non-nil only for a value that is present but
// undecodable, which is a parse failure and never an absence.
//
// It matches by submatch *index* rather than by submatch string because the
// two are not equivalent for the quoted branch: `"acct"<blob>=""` is a
// present-but-empty value, and reading it back as the empty string makes it
// indistinguishable from "the quoted branch did not participate". The hex
// branch cannot produce an empty value (it requires at least one hex digit),
// so an empty string from FindStringSubmatch means exactly one thing — and
// treating that one thing as unreadable is what made an empty account report
// as a broken keychain item.
func parseAttribute(re *regexp.Regexp, line string) (value string, ok bool, err error) {
	m := re.FindStringSubmatchIndex(line)
	if m == nil {
		return "", false, nil
	}
	if quoted := m[2]; quoted >= 0 {
		return line[quoted:m[3]], true, nil
	}
	decoded, err := hexDecode(line[m[4]:m[5]])
	if err != nil {
		return "", true, err
	}
	return decoded, true, nil
}

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
		account, ok, err := parseAttribute(acctRegexp, line)
		if !ok {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("malformed hex-encoded \"acct\" attribute: %w", err)
		}
		// An empty account is a value, not a failure: `security` renders it
		// as `"acct"<blob>=""`, and git does not guarantee a non-empty
		// username on a `store`, so cmd/gitcredential.go can create one.
		return account, nil
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

// classifySecurityError maps an error from runSecurity/runSecurityPrompt/
// findPassword/Delete onto the Backend error types callers switch on,
// mirroring classifyBusError (libsecret.go) and classifyCredError
// (wincred.go). Only the definitive errItemNotFound sentinel becomes
// *ErrNotFound; everything else — a timeout, a locked keychain, a missing
// binary, an unexpected exit code — becomes *ErrUnavailable via
// securityErrorReason, so "could not tell" is never reported as "not
// there".
//
// op names the operation for the diagnostic ("read", "delete"); it does not
// affect the returned type. It is a plain function, not a method: unlike
// before #68's review round, nothing it does depends on which *Keychain
// made the call — the one fact its timeout branch used to read off k
// (whether the call was interactive) now comes from the error itself, via
// wasPrompting. See securityTimeoutError's doc comment for why that changed.
func classifySecurityError(service, op string, err error) error {
	if errors.Is(err, errItemNotFound) {
		return &ErrNotFound{Service: service}
	}
	return &ErrUnavailable{Reason: securityErrorReason(fmt.Sprintf("could not %s keychain item for %q", op, service), err)}
}

// securityErrorReason renders err for an *ErrUnavailable diagnostic's
// Reason: a security timeout gets keychainPromptTimeoutReason's
// lock-vs-ACL disambiguation and, when applicable, its "stderr was not
// detected as a terminal" hint — a self-contained message that needs no
// further prefix — and anything else is reported as "<verbPhrase>: <err>".
//
// classifySecurityError uses this for the read/delete paths that also
// classify *ErrNotFound; Add and List use it directly, since a write or an
// enumeration failure has no "not found" outcome to classify but still
// deserves the same message construction. Before #68's review round Add
// and List built their *ErrUnavailable inline instead, which meant a
// timeout on the write path got a bare "%v" wrapping instead of
// keychainPromptTimeoutReason's disambiguation and hint — silently
// reintroducing #67's complaint on `secret set`/`secret list` after fixing
// it on the read/delete paths.
func securityErrorReason(verbPhrase string, err error) string {
	if errors.Is(err, errSecurityTimeout) {
		return keychainPromptTimeoutReason(err, wasPrompting(err))
	}
	return fmt.Sprintf("%s: %v", verbPhrase, err)
}

// keychainTimeoutCause is the causal explanation keychainTimeoutReason and
// keychainPromptTimeoutReason share: a timeout at either call site cannot
// by itself distinguish a keychain-unlock prompt from a per-item
// access-control prompt — both block the same synchronous `security`
// invocation the same way. Only the remedy differs between the two
// functions (see each's doc comment for why), so only the causal half is
// factored out.
const keychainTimeoutCause = "the security command did not respond in time, which can mean the keychain is locked with no agent able to answer an unlock prompt, or that a per-item access-control prompt is awaiting approval nothing can show"

// keychainTimeoutReason builds the *ErrUnavailable diagnostic for a
// show-keychain-info invocation that timed out (via runSecurity, from
// IsAvailable/keychainUnavailableReason). show-keychain-info cannot itself
// raise a dialog (see runSecurityPrompt's doc comment for the subcommands
// that can), so unlike keychainPromptTimeoutReason below there is no
// interactivity fact worth adding here: the bound it hit is
// securityCommandTimeout regardless of whether stderr is a terminal, so
// naming that would explain nothing.
//
// Its remedy does not point back at `security show-keychain-info`: that is
// the very command that just timed out, so telling the user to run it
// again is circular advice at this call site's only caller (IsAvailable),
// which issue #68's review round flagged this function for still doing
// after it was re-scoped to serve only that one caller. See
// keychainPromptTimeoutReason for the sibling that serves every other
// timeout classification in this file, whose remedy correctly does point
// at show-keychain-info — for those call sites it names a different
// command than the one that failed.
//
// It used to assert a single cause — "it may be locked with no agent able
// to answer an unlock prompt" — unconditionally. That is wrong whenever the
// real cause is an ACL authorization prompt instead (issue #44's PasswordsApp
// items are ACL-bound to their creating binary; a cross-binary read raises
// exactly this kind of prompt): measured hands-on on 2026-09-06, this
// message fired while `security show-keychain-info` simultaneously reported
// `no-timeout`, i.e. the keychain was demonstrably unlocked, and a user
// following the suggested remedy unlocks a keychain that was never locked
// and sees no improvement. A timeout at this call site cannot by itself
// distinguish the two, which is what keychainTimeoutCause now states once
// for both functions instead of asserting the single cause that used to be
// printed unconditionally.
func keychainTimeoutReason(err error) string {
	return fmt.Sprintf("keychain unavailable: %v — %s; open Keychain Access.app to check for a pending dialog, or retry once nothing else is contending for the keychain", err, keychainTimeoutCause)
}

// keychainPromptTimeoutReason builds the *ErrUnavailable diagnostic for a
// timed-out invocation that went through runSecurityPrompt, findPassword or
// Delete — find-generic-password, find-internet-password,
// add-generic-password, delete-generic-password, delete-internet-password,
// dump-keychain: every subcommand that can hand off to a keychain-unlock or
// per-item access-control dialog. Unlike keychainTimeoutReason, its remedy
// does point at `security show-keychain-info`: for these call sites that
// names a genuinely different command than the one that failed, so running
// it is not circular advice — see keychainTimeoutReason's own doc comment
// for the sibling call site where the same advice would be.
//
// wasInteractive answers "was this particular call given up to
// humanResponseTimeout to wait for a person", as recorded on the error that
// timed out (see wasPrompting) rather than read from any *Keychain's
// current field state. When it is true, that time already gave a person,
// if one was there, every reasonable chance to answer, so nothing more is
// known and nothing more is said. When it is false the additional fact is
// worth stating plainly: this call was bounded at the machine timeout
// instead, and so never actually waited out whatever raised it — which is
// otherwise indistinguishable from every other short-bound machine-call
// timeout this file can produce, and is exactly the "give me time to
// unlock" complaint issue #67 was filed over, happening again for a
// different, well-founded reason (this call was not given a chance to wait)
// rather than the original bug (it was, and got only the machine bound
// anyway).
func keychainPromptTimeoutReason(err error, wasInteractive bool) string {
	reason := fmt.Sprintf("keychain unavailable: %v — %s; check `security show-keychain-info` for the lock state before assuming either", err, keychainTimeoutCause)
	if wasInteractive {
		return reason
	}
	return reason + fmt.Sprintf(" — stderr was not detected as a terminal, so this call was bounded at the machine timeout above rather than given up to %s to wait for a person to answer a prompt; rerun from an interactive terminal if one needs answering", humanResponseTimeout)
}

func (k *Keychain) Add(service, account, password string) error {
	// -T names the real Apple binary deliberately, not k.security: the
	// non-interactive ACL grant it creates is the entire reason this backend
	// shells out to /usr/bin/security instead of using cgo (see AGENTS.md),
	// so it must never follow the test seam.
	_, err := k.runSecurityPrompt("add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", securityBinary,
		k.keychainPath,
	)
	if err != nil {
		// A write has no meaningful "not found" outcome, so this never
		// becomes *ErrNotFound the way classifySecurityError's read/delete
		// callers can — but it still routes through securityErrorReason for
		// the same message construction, so a timeout here gets the same
		// disambiguation and interactivity hint every other prompting call
		// site's diagnostic carries.
		return &ErrUnavailable{Reason: securityErrorReason(fmt.Sprintf("failed to add secret for '%s'", service), err)}
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
	//
	// The two calls share one promptOperationContext deadline rather than
	// each getting their own: see that function's doc comment for why, and
	// for what this does and does not bound.
	ctx, cancel, start := k.promptOperationContext()
	defer cancel()
	prompting := k.promptTimeout != 0

	_, err := k.runSecurityBoundedCtx(ctx, start, prompting, "delete-generic-password", "-s", service, k.keychainPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errItemNotFound) {
		return classifySecurityError(service, "delete", err)
	}

	if _, err := k.runSecurityBoundedCtx(ctx, start, prompting, "delete-internet-password", "-s", service, k.keychainPath); err != nil {
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
	out, err := k.runSecurityPrompt("dump-keychain", k.keychainPath)
	if err != nil {
		// Same reasoning as Add: no *ErrNotFound outcome to classify, but
		// still routed through securityErrorReason for the same message
		// construction classifySecurityError gives read/delete failures.
		return nil, &ErrUnavailable{Reason: securityErrorReason("failed to list secrets", err)}
	}
	services, err := parseKeychainDumpServices(out)
	if err != nil {
		return nil, &ErrUnavailable{Reason: fmt.Sprintf("failed to list secrets: %v", err)}
	}
	return services, nil
}

// parseKeychainDumpServices extracts the deduplicated, sorted set of service
// names from `security dump-keychain` output, matching "svce" (generic
// password) and "srvr" (internet password) attribute lines.
//
// An undecodable service name fails the whole enumeration rather than being
// skipped. Silently omitting it would make `secret list` return a
// complete-looking list with a service missing — no warning, no error, no
// exit code — while `secret password <that-service>` still hands the
// credential over. A truncated enumeration that looks whole is the one
// failure this function must not produce, so it is reported as what it is:
// output this package could not parse. (DedupeSortServices drops the empty
// name, which is not addressable by any other command.)
func parseKeychainDumpServices(dump string) ([]string, error) {
	var names []string
	for _, line := range strings.Split(dump, "\n") {
		name, ok, err := parseAttribute(svceRegexp, line)
		if !ok {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("malformed hex-encoded service attribute: %w", err)
		}
		names = append(names, name)
	}
	return DedupeSortServices(names), nil
}

// errItemNotFound is runSecurityBoundedCtx's internal sentinel for a
// definitive "no such item". Any other failure (locked keychain, missing
// binary, unexpected exit code) is returned as its own error instead, so
// callers can tell "absent" apart from "could not determine" rather than
// collapsing both into *ErrNotFound.
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

// securityPasswordLine matches the `password:` line `security
// find-generic-password -g` writes to stderr. Failure diagnostics interpolate
// stderr, and cmd/gitcredential.go documents that no error path from this
// package can carry a password value; redacting the line keeps that true even
// if security ever printed a secret alongside a non-zero exit.
//
// The whole line is matched rather than the quoted rendering alone, because
// `-g` has more than one: a password it cannot render as text is printed as
// `password: 0x<hex>  "<lossy>"`, which an anchored `^password: ".*"$` does
// not match at all. Nothing else security prints starts with `password: ` —
// its own diagnostics are prefixed `security: ` — so widening this costs no
// diagnostic. One case remains outside a line-oriented pattern: a password
// containing a newline puts its remainder on following lines that carry no
// marker of what they are. This is defense in depth for a stream that is only
// interpolated on failure, not the primary guarantee.
var securityPasswordLine = regexp.MustCompile(`(?m)^password: .*$`)

// runSecurity runs a security subcommand that cannot raise a dialog —
// show-keychain-info is currently the only one — bounded by k.timeout, so
// it must always fail fast regardless of interactivity: IsAvailable calls
// it from PersistentPreRunE ahead of every subcommand. Everything that can
// raise a keychain-unlock or ACL dialog goes through runSecurityPrompt
// instead. See runSecurityBoundedCtx for what a call bounded either way is
// classified into.
func (k *Keychain) runSecurity(args ...string) (string, error) {
	return k.runSecurityBounded(k.timeout, false, args...)
}

// runSecurityPrompt is runSecurity's counterpart for the security
// subcommands that can hand off to a keychain-unlock or per-item
// access-control dialog: find-generic-password, find-internet-password
// (via findPassword, which calls runSecurityBoundedCtx directly rather than
// through this function — see promptOperationContext), add-generic-password
// (Add), delete-generic-password and delete-internet-password (via Delete,
// same reason as findPassword), and dump-keychain (List).
//
// It is bounded by k.promptTimeout when that is set (i.e. newKeychain
// decided, via the injected interactive func, that someone is plausibly
// watching stderr) and falls back to k.timeout — byte-for-byte the same
// bound runSecurity uses — otherwise, so a non-interactive invocation (git
// credential helper, cron, CI, an ssh session with no tty on stderr) is
// unaffected by #67 and still fails within securityCommandTimeout.
//
// The known and accepted residual case is the inverse: an ssh session that
// does have a tty on stderr, but nobody at the console to answer a dialog
// it raises, now waits the full k.promptTimeout instead of failing in
// k.timeout. timeouts.go's humanResponseTimeout doc comment records the
// reasoning in full; in short, that costs latency on a path that was
// already broken, whereas the machine bound this replaces cost a user
// sitting right there their credential on a path that was working, and the
// asymmetry is the same one externalCallTimeout's own floor rests on
// (timeouts.go).
//
// What this function — and findPassword's and Delete's direct use of
// runSecurityBoundedCtx — do not bound: composition *across* Backend
// methods. See promptOperationContext's doc comment for what is bounded
// within one Keychain method and what still is not.
func (k *Keychain) runSecurityPrompt(args ...string) (string, error) {
	timeout := k.promptTimeout
	prompting := k.promptTimeout != 0
	if timeout == 0 {
		timeout = k.timeout
	}
	return k.runSecurityBounded(timeout, prompting, args...)
}

// promptOperationContext returns a context bounded by the prompt-eligible
// deadline for one Backend-interface operation, the wall-clock time it
// started, and whether that deadline is actually the prompt bound (as
// opposed to a fallback to k.timeout). findPassword and Delete each call
// this once, at the top of the method, and pass the same three values to
// each of their up-to-two security invocations — the generic-password
// attempt and, only on a definitive miss, the internet-password fallback —
// so the two share one window rather than each getting its own.
//
// Without this, GetPassword/GetUsername (findPassword: generic then
// internet) and Delete (generic then internet) could each take up to
// 2*humanResponseTimeout before returning — a fact humanResponseTimeout's
// own doc comment (timeouts.go) did not account for when it described
// itself as bounding "a command a user forgot they left waiting". With it,
// each Keychain method that can make more than one prompting call is
// bounded at a single humanResponseTimeout-scale wait, matching that
// description for the methods this package can bound that way.
//
// What this does not bound: composition *across* Backend methods —
// `git credential get` (GetUsername then GetPassword) and `secret set`
// (up to three Backend calls via cmd/set.go) still take a multiple of this
// window, because bounding those properly means threading a
// context.Context through the Backend interface across all four backends,
// which is a larger, separate change than this file can make on its own
// (raised, not resolved, in the review round for issue #67's PR). This is
// a deliberate, narrower fix: it bounds what a single *Keychain method* can
// be made to wait, not what a single `secret` invocation can be made to
// wait.
func (k *Keychain) promptOperationContext() (ctx context.Context, cancel context.CancelFunc, start time.Time) {
	bound := k.promptTimeout
	if bound == 0 {
		bound = k.timeout
	}
	ctx, cancel = context.WithTimeout(context.Background(), bound)
	return ctx, cancel, time.Now()
}

// runSecurityBounded creates a fresh single-call context bounded by timeout
// and delegates to runSecurityBoundedCtx. It exists for runSecurity and
// runSecurityPrompt, whose callers (Add, List, IsAvailable) each make at
// most one security invocation per Backend operation and so have no reason
// to share a deadline the way findPassword and Delete do — see
// promptOperationContext for the two-call case.
func (k *Keychain) runSecurityBounded(timeout time.Duration, prompting bool, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return k.runSecurityBoundedCtx(ctx, time.Now(), prompting, args...)
}

// runSecurityBoundedCtx runs the security CLI with the given arguments,
// bounded by ctx, and classifies the result: success returns stdout; a
// definitive "item not found" returns errItemNotFound; a timeout returns a
// *securityTimeoutError wrapping errSecurityTimeout; anything else (locked
// keychain, missing/non-executable binary, unexpected exit code) returns an
// error carrying whatever diagnostic security produced — plus the exit
// code itself, which is otherwise invisible to the user and is the only
// handle on an unmodelled failure.
//
// ctx, rather than a plain timeout duration, is what lets findPassword and
// Delete share one deadline across two calls (promptOperationContext);
// opStart is separate from ctx's own deadline because it names when the
// *operation* began, not when this particular call did — on a timeout, the
// diagnostic reports elapsed wall-clock time for the operation as a whole,
// which is the number worth knowing once two calls can share a deadline (a
// timeout on the second of two calls sharing one window would otherwise
// still report only that call's remaining time, understating how long the
// caller actually waited). prompting records whether ctx's deadline is
// actually a prompt bound, for securityTimeoutError to carry — see its doc
// comment for why that is captured here rather than re-derived later.
//
// The child is bounded via exec.CommandContext rather than a bare
// exec.Command, and WaitDelay bounds how long Wait will keep waiting on the
// stdout/stderr pipes once the child is gone. Without WaitDelay that wait is
// not a hard bound, because Stdout/Stderr are buffers rather than *os.File
// and Wait blocks until the pipes reach EOF — which a grandchild that
// inherited them and outlived the direct child would prevent even after the
// direct child itself has exited or been killed.
//
// What is and is not reproduced: on Go 1.26.4/darwin, killing a direct child
// that has no such grandchild — i.e. context cancellation alone, against a
// process with nothing else holding its pipes open — did not exhibit an
// unbounded wait either way; ctx's deadline made Run return on time with
// WaitDelay unset just as it did with it set. The unbounded wait is real and
// reproducible, but only via the grandchild-holding-the-pipe shape (see
// TestRunSecurity_WaitDelayBoundsGrandchildHoldingPipe), not via context
// cancellation of a childless direct child. cmd.Stdin is left nil, i.e.
// /dev/null, so the child can never block reading from an inherited terminal
// either.
func (k *Keychain) runSecurityBoundedCtx(ctx context.Context, opStart time.Time, prompting bool, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, k.security, args...)
	cmd.WaitDelay = securityWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := redactPasswords(strings.TrimSpace(stderr.String()))
		if ctx.Err() != nil {
			elapsed := time.Since(opStart).Round(time.Millisecond)
			// The child may have written a diagnostic before the deadline
			// killed it (e.g. "User interaction is not allowed" when no
			// agent can answer a prompt) — that is the one piece of
			// evidence that could tell an unlock prompt apart from an ACL
			// prompt, so surface it rather than discard it. It still cannot
			// be trusted to always be present or complete: the child may
			// have been killed before it wrote anything, which is why
			// keychainTimeoutCause still hedges between causes rather than
			// asserting one from this alone.
			base := fmt.Errorf("%w (security %s, elapsed %s)", errSecurityTimeout, args[0], elapsed)
			if msg != "" {
				base = fmt.Errorf("%w: %s", base, msg)
			}
			return "", &securityTimeoutError{err: base, prompting: prompting}
		}
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

// redactPasswords replaces the value on any `password:` line so that a secret
// cannot reach an error string.
func redactPasswords(s string) string {
	return securityPasswordLine.ReplaceAllString(s, "password: <redacted>")
}

func (k *Keychain) findPassword(service string, passwordOnly bool) (string, error) {
	var flag string
	if passwordOnly {
		flag = "-w"
	} else {
		flag = "-g"
	}

	// The generic and internet attempts share one promptOperationContext
	// deadline rather than each getting their own: see that function's doc
	// comment for why, and for what this does and does not bound.
	ctx, cancel, start := k.promptOperationContext()
	defer cancel()
	prompting := k.promptTimeout != 0

	// Try generic password first. A real failure here (not a "not found")
	// means we cannot determine whether the item exists at all, so return
	// immediately rather than masking it with an internet-password attempt.
	out, err := k.runSecurityBoundedCtx(ctx, start, prompting, "find-generic-password", flag, "-s", service, k.keychainPath)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, errItemNotFound) {
		return "", err
	}

	// Fall back to internet password.
	return k.runSecurityBoundedCtx(ctx, start, prompting, "find-internet-password", flag, "-s", service, k.keychainPath)
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
