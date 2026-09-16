package backend

import "testing"

// TestExternalCallTimeoutRespectsCap pins the shared default under the hard
// ceiling. The per-backend bounds derived from it are checked on their own
// platforms (keychain_test.go on darwin, libsecret_test.go on linux); this
// one runs everywhere, including the Windows job, so the policy cannot be
// broken at its source by a change nobody happened to test on macOS.
func TestExternalCallTimeoutRespectsCap(t *testing.T) {
	t.Parallel()
	if externalCallTimeout <= 0 {
		t.Fatalf("externalCallTimeout = %s; an unbounded or negative default defeats the point", externalCallTimeout)
	}
	if externalCallTimeout > maxExternalCallTimeout {
		t.Errorf("externalCallTimeout = %s, exceeds maxExternalCallTimeout (%s)",
			externalCallTimeout, maxExternalCallTimeout)
	}
}

// TestHumanResponseTimeoutExceedsExternalCallTimeout pins the shared
// wait-for-a-person bound above the machine bound it is applied instead of.
// It runs on every platform, unlike the callers of humanResponseTimeout
// (libsecret.go's promptWaitTimeout on linux, keychain.go's
// Keychain.promptTimeout on darwin), because the constant itself lives here,
// platform-agnostic.
//
// humanResponseTimeout is deliberately not checked against
// maxExternalCallTimeout: it bounds a wait on a person, not a machine, so
// the cap does not apply to it at all (see timeouts.go and
// TestSecurityBoundsRespectCap/TestDbusCallTimeoutRespectsCap, which exempt
// it on the same ground for the same reason). Asserting it here would
// encode the opposite rule.
func TestHumanResponseTimeoutExceedsExternalCallTimeout(t *testing.T) {
	t.Parallel()
	if humanResponseTimeout <= externalCallTimeout {
		t.Errorf("humanResponseTimeout (%s) <= externalCallTimeout (%s); the wait for a person must stay longer than the wait for a machine",
			humanResponseTimeout, externalCallTimeout)
	}
}

// TestHumanResponseTimeoutMeetsFloor is
// TestHumanResponseTimeoutExceedsExternalCallTimeout's other side: being
// longer than the machine bound is necessary but not sufficient for
// humanResponseTimeout to be useful for what it is named after. Without
// this, a value like 6 seconds — longer than externalCallTimeout's 5, but
// nowhere near "enough time for a person to read an unfamiliar dialog and
// type a password" — would pass every other check in this file while
// reintroducing #67's complaint at a different number. See
// humanResponseTimeoutFloor's doc comment for what 30 seconds is based on
// and why it is a judgement call rather than a measurement.
func TestHumanResponseTimeoutMeetsFloor(t *testing.T) {
	t.Parallel()
	if humanResponseTimeout < humanResponseTimeoutFloor {
		t.Errorf("humanResponseTimeout (%s) < humanResponseTimeoutFloor (%s); too short to be useful for the person it is named after",
			humanResponseTimeout, humanResponseTimeoutFloor)
	}
}
