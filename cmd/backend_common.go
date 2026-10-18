package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// knownBackendNames maps every SECRET_BACKEND value recognised on *any*
// platform to the GOOS value(s) it is valid on. cmd/backend_<os>.go files
// are build-tag separated and cannot reference each other's backend.*
// constructors, but a name is just a string, and keeping the full set here
// lets an unrecognised-value error on one platform tell a user who typed a
// name valid on a *different* platform (e.g. "secret-service" on macOS)
// apart from a genuine typo — see issue #7's design question 2. It is not
// used to select a backend, only to phrase this one error message; adding a
// backend elsewhere in this file does not make it selectable here.
var knownBackendNames = map[string][]string{
	"keychain":           {"darwin"},
	"passwords-app":      {"darwin"},
	"credential-manager": {"windows"},
	"secret-service":     {"linux"},
}

// errUnrecognisedBackend builds the error each platform's selectBackend
// returns for a SECRET_BACKEND value it does not accept. validHere lists
// the values accepted on goos (the running platform's GOOS, e.g. "darwin"),
// in the order they should be displayed.
//
// This repo has spent a whole campaign (#30/#32/#36/#42) removing silent
// fallbacks from ambiguous or unrecognised input, so an unrecognised
// SECRET_BACKEND value is a hard error here rather than a quiet fall-back
// to the platform default — see issue #7's design question 1.
func errUnrecognisedBackend(value, goos string, validHere []string) error {
	valid := strings.Join(validHere, ", ")
	if elsewhere, ok := knownBackendNames[value]; ok {
		return fmt.Errorf("SECRET_BACKEND=%q names a backend only available on %s, not %s; valid values here are: %s",
			value, strings.Join(elsewhere, ", "), goos, valid)
	}
	return fmt.Errorf("SECRET_BACKEND=%q is not a recognised backend; valid values here are: %s",
		value, valid)
}

// backendEnvValue returns the SECRET_BACKEND value every platform's backend
// selection must use, read via Viper (cmd/root.go maps the "backend" key to
// that env var). It is the one place the variable is read, so a new call
// site cannot forget to normalise it (issue #64).
//
// Surrounding whitespace is trimmed, because it is almost always an
// invisible accident (a trailing space or newline from a shell profile, a
// .env file or a CI variable) and otherwise surfaces as a confusing
// unrecognised-value error about a name that looks right. A value that is
// only whitespace therefore becomes "", i.e. the same as unset, which means
// the platform default.
//
// The value is deliberately NOT case-folded: "Keychain" stays an
// unrecognised-value error. That keeps to this repo's "fail explicitly,
// don't guess" stance on ambiguous input (see errUnrecognisedBackend); a
// wrong-case name is a typo to be reported, not silently accepted. Interior
// whitespace is also left alone, and shows up quoted in the error (control
// whitespace such as a tab escaped) because errUnrecognisedBackend formats
// the value with %q.
func backendEnvValue() string {
	return strings.TrimSpace(viper.GetString("backend"))
}
