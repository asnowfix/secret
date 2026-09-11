//go:build darwin

package cmd

import "github.com/asnowfix/secret/backend"

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
		"opt into the legacy Passwords.app backend instead of the Keychain default; NOTE: credentials it stores are ACL-bound to the creating binary, so `secret` and `git-credential-secret` cannot read each other's passwords back (issue #44)")
}

// selectBackend returns Keychain unless --passwords-app explicitly opts
// into the legacy PasswordsApp backend. This is also what
// git-credential-secret gets: cmd/git-credential-secret/main.go never
// builds the Cobra command tree, so forcePasswordsApp is never set to true
// for that binary and it always lands on Keychain, which is the entire
// point of #44 — the interop failure is between the two binaries, and both
// must land on the backend that actually round-trips passwords between
// them (Keychain.Add passes -T /usr/bin/security, so items it creates are
// readable by any binary rather than only the one that created them).
func selectBackend() backend.Backend {
	if forcePasswordsApp {
		return backend.NewPasswordsApp()
	}
	return backend.NewKeychain()
}
