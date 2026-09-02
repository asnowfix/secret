package cmd

import (
	"errors"
	"testing"

	"github.com/asnowfix/secret/backend"
)

// TestClassifySetTarget covers CRITICAL 1 from PR #29's review: a read
// failure that is not a definitive *backend.ErrNotFound must never be
// treated as "credential does not exist", since cmd/set.go skips the
// overwrite confirmation in that case.
func TestClassifySetTarget(t *testing.T) {
	t.Run("nil error means the credential exists", func(t *testing.T) {
		exists, indeterminate := classifySetTarget(nil)
		if !exists || indeterminate != nil {
			t.Fatalf("got (%v, %v), want (true, nil)", exists, indeterminate)
		}
	})

	t.Run("ErrNotFound means the credential is genuinely absent", func(t *testing.T) {
		exists, indeterminate := classifySetTarget(&backend.ErrNotFound{Service: "svc"})
		if exists || indeterminate != nil {
			t.Fatalf("got (%v, %v), want (false, nil)", exists, indeterminate)
		}
	})

	t.Run("wrapped ErrNotFound is still recognized", func(t *testing.T) {
		wrapped := errors.Join(errors.New("context"), &backend.ErrNotFound{Service: "svc"})
		exists, indeterminate := classifySetTarget(wrapped)
		if exists || indeterminate != nil {
			t.Fatalf("got (%v, %v), want (false, nil)", exists, indeterminate)
		}
	})

	t.Run("ErrUnavailable is indeterminate, not absent", func(t *testing.T) {
		exists, indeterminate := classifySetTarget(&backend.ErrUnavailable{Reason: "locked keyring"})
		if exists {
			t.Fatal("an indeterminate error must not report exists=true")
		}
		if indeterminate == nil {
			t.Fatal("an indeterminate error must be surfaced, not silently treated as 'does not exist'")
		}
	})

	t.Run("an arbitrary error is indeterminate, not absent", func(t *testing.T) {
		exists, indeterminate := classifySetTarget(errors.New("boom"))
		if exists {
			t.Fatal("an indeterminate error must not report exists=true")
		}
		if indeterminate == nil {
			t.Fatal("an indeterminate error must be surfaced, not silently treated as 'does not exist'")
		}
	})
}
