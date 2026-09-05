package cmd

import (
	"errors"
	"io"
	"os"
	"testing"
)

// fakeBackend is a minimal backend.Backend implementation for exercising
// command wiring without touching a real platform secret store.
type fakeBackend struct {
	services []string
	listErr  error
}

func (f *fakeBackend) IsAvailable() error                          { return nil }
func (f *fakeBackend) GetUsername(service string) (string, error)  { return "", nil }
func (f *fakeBackend) GetPassword(service string) (string, error)  { return "", nil }
func (f *fakeBackend) Add(service, account, password string) error { return nil }
func (f *fakeBackend) Delete(service string) error                 { return nil }
func (f *fakeBackend) Edit() error                                 { return nil }
func (f *fakeBackend) List() ([]string, error)                     { return f.services, f.listErr }

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read pipe: %v", err)
	}
	return string(out)
}

func TestListCmd_PrintsOneServicePerLine(t *testing.T) {
	orig := b
	defer func() { b = orig }()
	b = &fakeBackend{services: []string{"alpha", "beta", "gamma"}}

	out := captureStdout(t, func() {
		if err := listCmd.RunE(listCmd, nil); err != nil {
			t.Fatalf("RunE returned error: %v", err)
		}
	})

	want := "alpha\nbeta\ngamma\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestListCmd_EmptyBackendPrintsNothing(t *testing.T) {
	orig := b
	defer func() { b = orig }()
	b = &fakeBackend{services: []string{}}

	out := captureStdout(t, func() {
		if err := listCmd.RunE(listCmd, nil); err != nil {
			t.Fatalf("RunE returned error: %v", err)
		}
	})

	if out != "" {
		t.Errorf("output = %q, want empty", out)
	}
}

// TestListCmd_BackendErrorPropagates exercises fakeBackend.listErr, which
// previously sat unused: nothing verified that a List() failure (e.g. a
// backend that cannot distinguish "empty" from "denied") actually reaches
// the caller instead of being silently swallowed. RunE itself calls
// os.Exit(1) on error, so this drives the extracted runList() helper
// directly rather than killing the test process.
func TestListCmd_BackendErrorPropagates(t *testing.T) {
	orig := b
	defer func() { b = orig }()
	wantErr := errors.New("backend unavailable")
	b = &fakeBackend{listErr: wantErr}

	var gotErr error
	out := captureStdout(t, func() {
		gotErr = runList()
	})

	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("runList() error = %v, want %v", gotErr, wantErr)
	}
	if out != "" {
		t.Errorf("output = %q, want empty on error", out)
	}
}
