package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

func TestDeleteCredential(t *testing.T) {
	t.Run("deletes a single credential", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["svc"] = [2]string{"alice", "pw"}
		if err := deleteCredential(b, "svc"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := b.creds["svc"]; ok {
			t.Fatal("credential was not deleted")
		}
	})

	t.Run("ambiguous: errors with a remedy, still an ErrAmbiguous, nothing deleted", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["svc"] = [2]string{"alice", "pw"}
		b.deleteErr = &backend.ErrAmbiguous{Service: "svc", Count: 2}
		err := deleteCredential(b, "svc")
		var amb *backend.ErrAmbiguous
		if !errors.As(err, &amb) {
			t.Fatalf("got %v, want it to wrap *backend.ErrAmbiguous", err)
		}
		if !strings.Contains(err.Error(), "nothing was deleted") || !strings.Contains(err.Error(), "native tool") {
			t.Fatalf("got %q, want cause then remedy", err)
		}
		if _, ok := b.creds["svc"]; !ok {
			t.Fatal("credential was deleted despite ambiguity")
		}
	})

	t.Run("other errors pass through unchanged", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		err := deleteCredential(b, "svc")
		var nf *backend.ErrNotFound
		if !errors.As(err, &nf) {
			t.Fatalf("got %v, want *backend.ErrNotFound", err)
		}
	})
}

// TestRemoveOldCredential covers the delete step of `secret set`'s overwrite
// path (#49): ambiguity aborts, any other failure stays a warning.
func TestRemoveOldCredential(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["svc"] = [2]string{"alice", "pw"}
		var stderr bytes.Buffer
		if err := removeOldCredential(b, "svc", &stderr); err != nil || stderr.Len() != 0 {
			t.Fatalf("got err %v, stderr %q; want neither", err, stderr.String())
		}
	})

	t.Run("ambiguous aborts instead of warning", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["svc"] = [2]string{"alice", "pw"}
		b.deleteErr = &backend.ErrAmbiguous{Service: "svc", Count: 2}
		var stderr bytes.Buffer
		err := removeOldCredential(b, "svc", &stderr)
		var amb *backend.ErrAmbiguous
		if !errors.As(err, &amb) {
			t.Fatalf("got %v, want it to wrap *backend.ErrAmbiguous", err)
		}
		if !strings.Contains(err.Error(), "native tool") {
			t.Fatalf("got %q, want a remedy", err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("unexpected warning %q", stderr.String())
		}
	})

	t.Run("other delete failure is only a warning", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.deleteErr = &backend.ErrUnavailable{Reason: "keychain locked"}
		var stderr bytes.Buffer
		if err := removeOldCredential(b, "svc", &stderr); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(stderr.String(), "warning: could not remove old credential") {
			t.Fatalf("got stderr %q, want the warning", stderr.String())
		}
	})
}
