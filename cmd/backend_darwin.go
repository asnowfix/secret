//go:build darwin

package cmd

import (
	"fmt"
	"os"

	"github.com/asnowfix/secret/backend"
	"github.com/spf13/viper"
)

// forceKeychain backs the long-shipped, documented -k/--keychain flag.
// Keychain is now the default (see below), so this flag no longer changes
// which backend is selected — it is kept, still parsed, and still means
// exactly what it always meant ("use the Keychain backend"), so that a
// script or shell alias with -k baked in keeps doing the same thing rather
// than silently taking on a new meaning. It intentionally has no effect on
// selectBackend's outcome any more.
var forceKeychain bool

// forcePasswordsApp is the explicit opt-in for the legacy PasswordsApp
// backend, per #44's maintainer decision: PasswordsApp stops being the
// macOS default because a credential it stores is ACL-bound to whichever
// binary created it, so `secret` and `git-credential-secret` cannot read
// each other's passwords back (#44). It is not removed — pass
// --passwords-app to opt into it explicitly, with that trade-off understood.
var forcePasswordsApp bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&forceKeychain, "keychain", "k", false,
		"use the Keychain backend (login.keychain-db via /usr/bin/security) — this is the default; the flag is a no-op kept for backward compatibility")
	rootCmd.PersistentFlags().BoolVar(&forcePasswordsApp, "passwords-app", false,
		"opt into the legacy Passwords.app backend instead of the Keychain default; NOTE: credentials it stores are ACL-bound to the creating binary, so secret and git-credential-secret cannot read each other's passwords back (issue #44)")
}

// darwinBackendNames lists the SECRET_BACKEND values accepted on macOS, in
// display order for errUnrecognisedBackend.
var darwinBackendNames = []string{"keychain", "passwords-app"}

// selectBackend returns Keychain unless overridden. Two overrides exist,
// and --passwords-app wins when both are given (issue #7's design
// question 3): it is a deliberate, per-invocation choice made at the call
// site, whereas SECRET_BACKEND is typically inherited from a shell profile
// or CI environment and set once for a whole session or host. A script
// that hardcodes --passwords-app for one specific call should not have
// that silently overridden by an environment it doesn't control. This also
// matches the conventional flag-over-env precedence Cobra/Viper CLIs
// generally follow. Because the flag alone fully determines the outcome
// when set, SECRET_BACKEND does not affect it — an unrelated typo in an
// inherited environment variable should not break an invocation the flag
// already resolves unambiguously. SECRET_BACKEND is, however, still
// validated on this path (see validateBackendEnvIgnoredByFlag below), and a
// value this platform would otherwise reject is reported on stderr: without
// that, a user with --passwords-app aliased in their shell profile could
// carry a broken SECRET_BACKEND unnoticed for weeks, since --passwords-app
// masks it, until git-credential-secret — which cannot take the flag at
// all, by design — hits the same broken variable cold and reports it as a
// hard error instead of a warning (see RunGitCredentialHelper).
//
// This is also what git-credential-secret gets: cmd/git-credential-secret/
// main.go never builds the Cobra command tree, so forcePasswordsApp is
// never set to true for that binary, but SECRET_BACKEND still reaches it
// (see RunGitCredentialHelper's doc comment for why that is intentional,
// issue #7's design question 5). Absent both overrides it always lands on
// Keychain, which is the entire point of #44 — the interop failure is
// between the two binaries, and both must land on the backend that
// actually round-trips passwords between them (Keychain.Add passes -T
// /usr/bin/security, so items it creates are readable by any binary rather
// than only the one that created them).
func selectBackend() (backend.Backend, error) {
	if forcePasswordsApp {
		validateBackendEnvIgnoredByFlag()
		return backend.NewPasswordsApp(), nil
	}
	return resolveBackendName(viper.GetString("backend"))
}

// resolveBackendName is the single source of truth for "which SECRET_BACKEND
// values darwin accepts": it is the only place that lists them, and both
// selectBackend's normal (non-flag) path and validateBackendEnvIgnoredByFlag
// below call it, so the two cannot drift apart the way darwinBackendNames
// and this switch once could (see the review that added this function:
// validateBackendEnvIgnoredByFlag originally carried its own hand-written
// copy of this switch's cases, a fourth hand-synchronised list alongside
// the three "must fix 1" in PR #63's review already addressed).
func resolveBackendName(name string) (backend.Backend, error) {
	switch name {
	case "":
		return backend.NewKeychain(), nil
	case "keychain":
		return backend.NewKeychain(), nil
	case "passwords-app":
		return backend.NewPasswordsApp(), nil
	default:
		return nil, errUnrecognisedBackend(name, "darwin", darwinBackendNames)
	}
}

// validateBackendEnvIgnoredByFlag reports, on stderr, a SECRET_BACKEND
// value that --passwords-app is about to override without ever reading —
// see selectBackend's doc comment above for why the flag still wins
// unconditionally. It reuses resolveBackendName purely for its error,
// discarding the backend, rather than re-deciding validity itself: that is
// what keeps this path from being able to disagree with selectBackend's own
// switch about which names are valid. A value that is merely a different
// valid choice than the flag's (e.g. SECRET_BACKEND=keychain alongside
// --passwords-app) resolves without error and stays silent — that's the
// ordinary, working precedence case. A warning rather than an error because
// the invocation must still succeed: the whole point of the flag winning is
// that a script or alias with --passwords-app baked in keeps working
// regardless of what an inherited environment variable holds.
func validateBackendEnvIgnoredByFlag() {
	name := viper.GetString("backend")
	if _, err := resolveBackendName(name); err != nil {
		fmt.Fprintf(os.Stderr, "secret: warning: %v (ignored: --passwords-app was given)\n", err)
	}
}
