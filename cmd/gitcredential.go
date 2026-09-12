package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/asnowfix/secret/backend"
)

// This file implements git's credential-helper protocol (get/store/erase)
// on top of the same backend.Backend used by the ordinary `secret`
// subcommands (login, password, set, delete). It is deliberately not wired
// up as a `secret` subcommand: see cmd/git-credential-secret/main.go for why
// this has to be a standalone binary, and for why keeping the protocol's
// plaintext-password-to-stdout mode (get) out of the Cobra command tree
// bounds it to one intentional entry point rather than something a mistyped
// ordinary subcommand could ever trigger.

// gitCredentialInput holds the attributes git sends on a credential-helper
// invocation's stdin. See gitcredentials(7) and the "INPUT/OUTPUT FORMAT"
// section of git-credential(1): one "key=value" pair per line, terminated
// by a blank line or EOF. Only the attributes this helper acts on are kept;
// anything else (authtype, credential, password_expiry_utc,
// oauth_refresh_token, ...) is read and silently discarded, per spec
// ("Unrecognised attributes are silently discarded").
type gitCredentialInput struct {
	protocol string
	host     string
	path     string
	username string
	password string
}

// parseGitCredentialInput reads a blank-line-terminated set of key=value
// attributes from r. A malformed line (no "=") is ignored rather than
// treated as an error, matching git's own tolerance for unrecognised
// attributes.
//
// The special "url" attribute is supported per git-credential(1) ("the
// value is parsed as a URL and treated as if its constituent parts were
// read"), even though real `git`, when driving a configured
// credential.helper, sends protocol/host/path/username split out rather
// than as a single url= line — url= mainly matters for hand-built input
// (e.g. `git credential fill` piped by a script, or manual testing of this
// binary). Values from split attributes always take precedence over a url=
// line that appears earlier, since later lines are meant to refine earlier
// ones.
func parseGitCredentialInput(r io.Reader) (gitCredentialInput, error) {
	var in gitCredentialInput
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "protocol":
			in.protocol = value
		case "host":
			in.host = value
		case "path":
			in.path = value
		case "username":
			in.username = value
		case "password":
			in.password = value
		case "url":
			applyGitCredentialURL(&in, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return in, err
	}
	return in, nil
}

// applyGitCredentialURL fills in whichever of protocol/host/path/username
// are present in a "url=" attribute's value, per git-credential(1)'s
// description of that attribute.
func applyGitCredentialURL(in *gitCredentialInput, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if u.Scheme != "" {
		in.protocol = u.Scheme
	}
	if u.Host != "" {
		in.host = u.Host
	}
	if u.Path != "" {
		in.path = strings.TrimPrefix(u.Path, "/")
	}
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			in.username = name
		}
	}
}

// gitCredentialServiceKey collapses a credential-helper request's
// protocol/host/path tuple into the single flat service string
// backend.Backend is keyed on (see backend/backend.go). Returns "" if there
// is nothing usable to key on.
//
// It is deliberately keyed on host alone — protocol dropped, path folded in
// only when git actually sent one — rather than a namespaced key such as
// "protocol://host/path":
//
//   - Interop with the plain `secret` CLI is, per the issue's dispatch
//     brief, most of this feature's value: a credential a user stored by
//     hand via `secret set github.com <user> <token>` must be found by
//     `git push` against `https://github.com/...` without the user doing
//     anything helper-specific. A namespaced key like
//     "git:https://github.com" would silently defeat that, since it would
//     never match a plain "github.com" entry.
//   - gitcredentials(7) confirms path does not normally participate: "By
//     default, Git does not consider the 'path' component of an http URL
//     to be worth matching via external helpers" — i.e. unless
//     credential.useHttpPath is set for that context, git never even sends
//     a path attribute to external helpers in the first place. So this
//     function does not decide on its own whether path matters: it simply
//     folds in whatever path the request actually carried (possibly none),
//     which keeps get/store/erase symmetric for a given git config without
//     ever inventing a path git did not send.
//   - Protocol is dropped for the same interop reason: `secret set` has no
//     notion of protocol, and a host being reachable over both an
//     authenticated http(s) remote and some other credential-consuming
//     protocol (e.g. smtp for git send-email) with genuinely different
//     credentials worth keeping apart is rare. A user who does need that
//     separation can still get it by turning on credential.useHttpPath and
//     relying on path instead.
//   - None of the three backends (macOS Keychain via /usr/bin/security's
//     -s flag, Windows Credential Manager's TargetName, Linux Secret
//     Service's "service" D-Bus string attribute) restrict the character
//     set of a service string, so a host[:port] or host/path value never
//     needs escaping here.
func gitCredentialServiceKey(in gitCredentialInput) string {
	if in.host == "" {
		return ""
	}
	if in.path == "" {
		return in.host
	}
	return in.host + "/" + strings.TrimPrefix(in.path, "/")
}

// RunGitCredentialHelper implements the git credential-helper protocol for
// op ("get", "store", or "erase"; see gitcredentials(7)), reading the
// request from stdin and, for "get", writing the answer to stdout. It
// selects a backend the same way the ordinary `secret` subcommands do
// (selectBackend, defined per-platform in cmd/backend_*.go) and always
// returns 0 unless invoked with an operation git itself would never send —
// see runGitCredentialHelper below for why a missing credential or an
// unavailable backend must never be reported as a failure.
//
// This deliberately honours SECRET_BACKEND (issue #7's design question 5):
// this binary never builds the Cobra command tree, so --passwords-app is
// unreachable from it, but selectBackend() is the same shared function the
// `secret` binary calls, and it was already going to vary by platform build
// tag before this change — letting an environment variable vary it too adds
// no new entry point to the security-sensitive "get" operation described in
// this file's and cmd/git-credential-secret/main.go's package doc comments
// (that boundary is about which *operations* are reachable only through
// this binary, not about which backend answers them). Leaving it unhonoured
// here instead would mean `secret set` and `git-credential-secret` could
// silently disagree about which store is authoritative whenever
// SECRET_BACKEND is set, which is a worse failure mode than a config
// mistake surfacing as a diagnostic on stderr below.
func RunGitCredentialHelper(op string, stdin io.Reader, stdout, stderr io.Writer) int {
	b, err := selectBackend()
	if err != nil {
		// Same reasoning as the ErrUnavailable case in
		// runGitCredentialHelper: git ignores this helper's exit code and
		// must fall through to its next configured helper or an
		// interactive prompt rather than see a hard failure, so this is
		// reported on stderr for a human, not surfaced as a non-zero exit.
		fmt.Fprintf(stderr, "git-credential-secret: %v\n", err)
		return 0
	}
	return runGitCredentialHelper(b, op, stdin, stdout, stderr)
}

// runGitCredentialHelper is RunGitCredentialHelper with the backend
// injected, so it can be exercised in tests against a fake backend.Backend
// without touching a real platform secret store.
func runGitCredentialHelper(b backend.Backend, op string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := b.IsAvailable(); err != nil {
		// From git's point of view, a backend that cannot be reached right
		// now (locked keychain, no D-Bus session, ...) is indistinguishable
		// from "no credential found": either way, git must fall through to
		// the next configured helper or to an interactive prompt, never see
		// a hard failure from this one. Reported on stderr for a human
		// debugging the helper directly; ErrUnavailable's Reason is a fixed,
		// backend-authored diagnostic string and never derived from a
		// credential value, so it is safe to print here.
		fmt.Fprintf(stderr, "git-credential-secret: backend unavailable: %v\n", err)
		return 0
	}

	in, err := parseGitCredentialInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "git-credential-secret: failed to read request: %v\n", err)
		return 0
	}

	switch op {
	case "get":
		gitCredentialGet(b, in, stdout)
	case "store":
		gitCredentialStore(b, in, stderr)
	case "erase":
		gitCredentialErase(b, in, stderr)
	default:
		// gitcredentials(7): "If a helper receives any other operation, it
		// should silently ignore the request. This leaves room for future
		// operations to be added."
	}
	return 0
}

// gitCredentialGet answers a "get" request. It writes nothing and leaves
// stdout untouched whenever there is no matching credential, no service to
// key on, or the request narrows to a username this backend does not have
// — a miss is a normal outcome, not an error (see gitcredentials(7):
// "A helper is free to produce ... no values at all if it has nothing
// useful to provide").
func gitCredentialGet(b backend.Backend, in gitCredentialInput, stdout io.Writer) {
	service := gitCredentialServiceKey(in)
	if service == "" {
		return
	}
	username, err := b.GetUsername(service)
	if err != nil {
		// Deliberately not logged, even to stderr: on a re-locked keyring or
		// similar transient failure this error could in principle echo back
		// partial credential state, and there is nothing a git user could do
		// with it anyway — a miss is a miss from git's perspective either
		// way.
		return
	}
	if in.username != "" && in.username != username {
		// Git supplied a username to narrow the match (e.g. from a
		// https://user@host/... remote URL). This backend keeps one
		// username per service, so if it doesn't match, there is nothing to
		// offer for the username git actually asked about.
		return
	}
	password, err := b.GetPassword(service)
	if err != nil {
		return
	}
	fmt.Fprintf(stdout, "username=%s\n", username)
	fmt.Fprintf(stdout, "password=%s\n", password)
}

// gitCredentialStore persists a credential git obtained interactively (or
// from another helper). Errors are reported to stderr only as fixed,
// backend-authored diagnostic strings (see the doc comment on
// gitCredentialGet's ErrUnavailable case, and backend/keychain.go,
// backend/wincred.go, backend/libsecret.go: none of their Add/Delete error
// paths interpolate a password value into the returned error), never the
// password itself; git ignores a store operation's output and exit code
// either way (gitcredentials(7): "For a store or erase operation, the
// helper's output is ignored").
func gitCredentialStore(b backend.Backend, in gitCredentialInput, stderr io.Writer) {
	service := gitCredentialServiceKey(in)
	if service == "" || in.password == "" {
		return
	}
	// Add is not guaranteed to replace an existing credential on every
	// backend — the macOS Keychain backend's `security add-generic-password`
	// fails on a duplicate rather than overwriting it — so remove any
	// existing entry first, mirroring `secret set`'s overwrite path
	// (cmd/set.go). Not finding one to remove is the common case, not a
	// failure worth reporting.
	if err := b.Delete(service); err != nil {
		var notFound *backend.ErrNotFound
		if !errors.As(err, &notFound) {
			fmt.Fprintf(stderr, "git-credential-secret: could not remove existing credential for '%s' before store: %v\n", service, err)
		}
	}
	if err := b.Add(service, in.username, in.password); err != nil {
		fmt.Fprintf(stderr, "git-credential-secret: failed to store credential for '%s': %v\n", service, err)
	}
}

// gitCredentialErase removes a stored credential git has determined is
// wrong. If the request carries a username and it does not match what is
// currently stored, the credential is left alone — it is not the one git is
// asking to erase. If the request carries a username and the stored one
// cannot be read at all, the erase is refused rather than guessed at: see
// classifyEraseTarget.
func gitCredentialErase(b backend.Backend, in gitCredentialInput, stderr io.Writer) {
	service := gitCredentialServiceKey(in)
	if service == "" {
		return
	}
	if in.username != "" {
		current, err := b.GetUsername(service)
		proceed, indeterminate := classifyEraseTarget(in.username, current, err)
		if indeterminate != nil {
			// A fixed, backend-authored diagnostic string, never a
			// credential value — same reasoning as the ErrUnavailable case
			// documented on gitCredentialGet. git ignores an erase's output
			// (gitcredentials(7)), so this is for a human wondering why the
			// credential is still there.
			//
			// Cause first, remedy second, following
			// keychainUnavailableReason (backend/keychain.go). The remedy is
			// not decoration here: refusing leaves git retrying against a
			// credential it knows is bad, and this line is the only thing
			// that tells the user how to break out of that. It has to stand
			// on its own, too — a helper's stderr reaches a human at a
			// terminal, but GUI clients (VS Code, Sourcetree, GitKraken)
			// discard it, so anyone who does see it may be seeing it out of
			// context, and some refusals (an item whose account attribute
			// cannot be parsed at all) repeat forever rather than clearing
			// on the next attempt.
			fmt.Fprintf(stderr, "git-credential-secret: could not determine which username is stored for '%s', refusing to erase a credential that may not be the one git asked about: %v — retry once the store is readable, or remove it by hand with `secret delete %s`\n", service, indeterminate, service)
			return
		}
		if !proceed {
			return
		}
	}
	if err := b.Delete(service); err != nil {
		var notFound *backend.ErrNotFound
		if !errors.As(err, &notFound) {
			fmt.Fprintf(stderr, "git-credential-secret: failed to erase credential for '%s': %v\n", service, err)
		}
	}
}

// classifyEraseTarget decides whether an erase request that named a
// username may delete the stored credential for that service, given the
// username currently stored (current) and the error GetUsername returned
// while reading it.
//
// It is the erase-side counterpart of classifySetTarget (cmd/set.go) and
// exists for the same reason: a failed read is not an answer. GetUsername
// can fail on any backend for reasons that say nothing about who is stored
// — a locked keychain, a stale D-Bus session, a transport fault, a timeout,
// an item whose account attribute cannot be parsed — while Delete still
// succeeds afterwards. Letting the delete run in that case means an erase
// naming bob destroys alice's credential, so only a definitive answer
// authorises it:
//
//   - read succeeded: proceed only on an exact match, as before.
//   - *backend.ErrNotFound: proceed. Not because the delete achieves
//     anything — every backend's read covers at least what its Delete
//     covers (on macOS GetUsername looks at generic then internet items,
//     where Delete reaches the internet class only after a definitive
//     generic miss; on Linux both hinge on the same searchItems result), so
//     where the two agree this branch is a no-op. It proceeds because
//     *ErrNotFound is each backend's contract for "definitively absent"
//     (backend/backend.go), and a definitive answer is precisely what this
//     function asks for; Delete's own ErrNotFound is then swallowed as the
//     normal outcome it is. One backend currently breaks that contract:
//     see #48, where wincred returns *ErrNotFound after CredReadW
//     succeeded but UserName was NULL, i.e. for a credential that does
//     exist. That is a violation of the contract rather than a flaw in
//     relying on it, predates this function (the previous guard fell
//     through to Delete identically), and is fixed there rather than
//     worked around here.
//   - anything else: indeterminate, handed back for the caller to refuse
//     on rather than guessed at.
//
// runGitCredentialHelper's IsAvailable check is no protection against any
// of this, for two different reasons depending on backend (this paragraph
// used to give one reason for both; it stopped being true for macOS once
// #44 made Keychain the default there instead of PasswordsApp — the
// conclusion survives, the premise below is corrected and now measured
// rather than reasoned).
//
// On Windows, CredentialManager's IsAvailable merely loads advapi32 and
// never touches the store at all, so it establishes nothing about any
// particular credential — a later indeterminate read may never have had
// anything to go stale from.
//
// On macOS, Keychain's IsAvailable shells out to `security
// show-keychain-info`, which does touch the store — but only enough to
// confirm the keychain itself is unlocked, not that any particular item is
// readable. An item still ACL-bound to a different binary (issue #44,
// including credentials stored under the pre-#44 PasswordsApp default) can
// time out on its own find-generic-password call immediately afterward.
// Measured 2026-09-11: IsAvailable passed (the keychain was genuinely
// unlocked) while the very next per-item read against such a credential
// timed out. So a passing IsAvailable establishes the keychain is open, not
// that this item is readable — the argument is stronger here than on
// Windows, not weaker, just for a different reason.
//
// Refusing has a cost of its own — git cannot clear a credential it knows
// is bad, so it may keep retrying against the stale one — but it is
// recoverable by hand (retry once the store is readable, or `secret delete
// <service>`), whereas erasing another user's credential is silent and
// irreversible. Not every refusal clears on retry: an item whose account
// attribute cannot be parsed refuses every time, which is why the caller's
// message carries the remedy and not only the cause.
//
// Nor is this the corner case it may look like: git's credential_reject()
// sends every attribute it holds, username included, so after a fill this
// helper served the guarded path is the ordinary reject path rather than
// an unusual one. An erase naming no username — asking for whatever is
// stored under that service, with no username to be wrong about — is the
// exception, and is unaffected.
//
// What this bounds, and what it does not: it stops an unverified username
// authorising a delete. It does not make a verified one safe on its own.
// Per #49, Delete removes every item matching the service while the read
// picks one, so where two credentials share a service an erase matching
// bob can still take alice's with it — the guard passes and the harm
// happens anyway.
func classifyEraseTarget(want, current string, err error) (proceed bool, indeterminate error) {
	if err == nil {
		return current == want, nil
	}
	var notFound *backend.ErrNotFound
	if errors.As(err, &notFound) {
		return true, nil
	}
	return false, err
}
