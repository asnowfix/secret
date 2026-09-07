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
