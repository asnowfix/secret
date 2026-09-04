package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

// fakeGitCredentialBackend is a minimal, in-memory backend.Backend used to
// exercise the git credential-helper protocol logic without touching any
// real platform secret store.
type fakeGitCredentialBackend struct {
	available error
	creds     map[string][2]string // service -> [account, password]

	addCalls    []string
	deleteCalls []string
}

func newFakeGitCredentialBackend() *fakeGitCredentialBackend {
	return &fakeGitCredentialBackend{creds: map[string][2]string{}}
}

func (f *fakeGitCredentialBackend) IsAvailable() error { return f.available }

func (f *fakeGitCredentialBackend) GetUsername(service string) (string, error) {
	c, ok := f.creds[service]
	if !ok {
		return "", &backend.ErrNotFound{Service: service}
	}
	return c[0], nil
}

func (f *fakeGitCredentialBackend) GetPassword(service string) (string, error) {
	c, ok := f.creds[service]
	if !ok {
		return "", &backend.ErrNotFound{Service: service}
	}
	return c[1], nil
}

func (f *fakeGitCredentialBackend) Add(service, account, password string) error {
	f.addCalls = append(f.addCalls, service)
	f.creds[service] = [2]string{account, password}
	return nil
}

func (f *fakeGitCredentialBackend) Delete(service string) error {
	f.deleteCalls = append(f.deleteCalls, service)
	if _, ok := f.creds[service]; !ok {
		return &backend.ErrNotFound{Service: service}
	}
	delete(f.creds, service)
	return nil
}

func (f *fakeGitCredentialBackend) Edit() error { return nil }

func (f *fakeGitCredentialBackend) List() ([]string, error) {
	services := make([]string, 0, len(f.creds))
	for service := range f.creds {
		services = append(services, service)
	}
	return services, nil
}

var _ backend.Backend = (*fakeGitCredentialBackend)(nil)

func TestParseGitCredentialInput(t *testing.T) {
	t.Run("split attributes", func(t *testing.T) {
		in, err := parseGitCredentialInput(strings.NewReader("protocol=https\nhost=github.com\nusername=bob\n\ntrailing garbage after blank line\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := gitCredentialInput{protocol: "https", host: "github.com", username: "bob"}
		if in != want {
			t.Fatalf("got %+v, want %+v", in, want)
		}
	})

	t.Run("url attribute", func(t *testing.T) {
		in, err := parseGitCredentialInput(strings.NewReader("url=https://alice@example.com/foo.git\n\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := gitCredentialInput{protocol: "https", host: "example.com", path: "foo.git", username: "alice"}
		if in != want {
			t.Fatalf("got %+v, want %+v", in, want)
		}
	})

	t.Run("split attributes after url refine it", func(t *testing.T) {
		in, err := parseGitCredentialInput(strings.NewReader("url=https://example.com/foo.git\nusername=carol\n\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if in.username != "carol" {
			t.Fatalf("got username %q, want %q", in.username, "carol")
		}
	})

	t.Run("malformed line is ignored, not an error", func(t *testing.T) {
		in, err := parseGitCredentialInput(strings.NewReader("host=example.com\nnotakeyvaluepair\n\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if in.host != "example.com" {
			t.Fatalf("got host %q, want %q", in.host, "example.com")
		}
	})

	t.Run("no blank line, terminated by EOF", func(t *testing.T) {
		in, err := parseGitCredentialInput(strings.NewReader("host=example.com"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if in.host != "example.com" {
			t.Fatalf("got host %q, want %q", in.host, "example.com")
		}
	})
}

func TestGitCredentialServiceKey(t *testing.T) {
	cases := []struct {
		name string
		in   gitCredentialInput
		want string
	}{
		{"empty host yields empty key", gitCredentialInput{}, ""},
		{"host only, interop with plain secret set", gitCredentialInput{protocol: "https", host: "github.com"}, "github.com"},
		{"host plus path when git sent one (useHttpPath)", gitCredentialInput{host: "example.com", path: "foo/bar.git"}, "example.com/foo/bar.git"},
		{"leading slash in path is not duplicated", gitCredentialInput{host: "example.com", path: "/foo.git"}, "example.com/foo.git"},
		{"protocol never participates", gitCredentialInput{protocol: "ssh", host: "example.com"}, "example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gitCredentialServiceKey(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRunGitCredentialHelper_Get(t *testing.T) {
	t.Run("unknown host: exit 0, nothing written", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=unknown.example\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("got stdout %q, want empty", stdout.String())
		}
	})

	t.Run("known host: username and password written", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		got := stdout.String()
		if !strings.Contains(got, "username=bob\n") || !strings.Contains(got, "password=s3cr3t\n") {
			t.Fatalf("got stdout %q, want it to contain username=bob and password=s3cr3t", got)
		}
	})

	t.Run("username narrows the match: mismatch yields nothing", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\nusername=alice\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("got stdout %q, want empty (username did not match)", stdout.String())
		}
	})

	t.Run("username narrows the match: match yields the credential", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\nusername=bob\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "password=s3cr3t\n") {
			t.Fatalf("got stdout %q, want it to contain password=s3cr3t", stdout.String())
		}
	})

	t.Run("interop: a credential stored by plain 'secret set' is found by git get", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		// Simulates `secret set github.com bob s3cr3t`.
		if err := b.Add("github.com", "bob", "s3cr3t"); err != nil {
			t.Fatalf("Add: %v", err)
		}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "username=bob\n") || !strings.Contains(stdout.String(), "password=s3cr3t\n") {
			t.Fatalf("got stdout %q, want the manually-stored credential", stdout.String())
		}
	})

	t.Run("unavailable backend: exit 0, nothing on stdout", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.available = &backend.ErrUnavailable{Reason: "keychain locked"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("got stdout %q, want empty", stdout.String())
		}
	})

	t.Run("password never appears on stderr", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t-marker"}
		var stdout, stderr bytes.Buffer
		runGitCredentialHelper(b, "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if strings.Contains(stderr.String(), "s3cr3t-marker") {
			t.Fatalf("password leaked onto stderr: %q", stderr.String())
		}
	})
}

func TestRunGitCredentialHelper_Store(t *testing.T) {
	t.Run("persists where a plain get can find it", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "store", strings.NewReader("protocol=https\nhost=github.com\nusername=bob\npassword=s3cr3t\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		got, ok := b.creds["github.com"]
		if !ok {
			t.Fatal("credential was not stored under the host-only service key")
		}
		if got[0] != "bob" || got[1] != "s3cr3t" {
			t.Fatalf("got %+v, want [bob s3cr3t]", got)
		}
	})

	t.Run("overwrites an existing credential", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"old", "old-pw"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "store", strings.NewReader("protocol=https\nhost=github.com\nusername=new\npassword=new-pw\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		got := b.creds["github.com"]
		if got[0] != "new" || got[1] != "new-pw" {
			t.Fatalf("got %+v, want [new new-pw]", got)
		}
	})

	t.Run("no password: nothing is stored", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		var stdout, stderr bytes.Buffer
		runGitCredentialHelper(b, "store", strings.NewReader("protocol=https\nhost=github.com\nusername=bob\n\n"), &stdout, &stderr)
		if len(b.addCalls) != 0 {
			t.Fatalf("Add was called with no password present: %v", b.addCalls)
		}
	})

	t.Run("password never appears on stderr, even on a partial failure", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		var stdout, stderr bytes.Buffer
		runGitCredentialHelper(b, "store", strings.NewReader("protocol=https\nhost=github.com\nusername=bob\npassword=s3cr3t-marker\n\n"), &stdout, &stderr)
		if strings.Contains(stderr.String(), "s3cr3t-marker") {
			t.Fatalf("password leaked onto stderr: %q", stderr.String())
		}
	})
}

func TestRunGitCredentialHelper_Erase(t *testing.T) {
	t.Run("removes a stored credential", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t"}
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "erase", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
		if _, ok := b.creds["github.com"]; ok {
			t.Fatal("credential was not erased")
		}
	})

	t.Run("erasing an already-absent credential is not an error", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		var stdout, stderr bytes.Buffer
		code := runGitCredentialHelper(b, "erase", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("got exit code %d, want 0", code)
		}
	})

	t.Run("username mismatch leaves the stored credential alone", func(t *testing.T) {
		b := newFakeGitCredentialBackend()
		b.creds["github.com"] = [2]string{"bob", "s3cr3t"}
		var stdout, stderr bytes.Buffer
		runGitCredentialHelper(b, "erase", strings.NewReader("protocol=https\nhost=github.com\nusername=alice\n\n"), &stdout, &stderr)
		if _, ok := b.creds["github.com"]; !ok {
			t.Fatal("credential for a different username was erased")
		}
	})
}

func TestRunGitCredentialHelper_UnknownOperation(t *testing.T) {
	b := newFakeGitCredentialBackend()
	var stdout, stderr bytes.Buffer
	code := runGitCredentialHelper(b, "capability", strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("got exit code %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("got stdout %q, want empty", stdout.String())
	}
}

// TestFakeBackendSatisfiesErrNotFoundContract guards against the fake
// backend's Delete/GetUsername/GetPassword drifting from the real
// backends' contract of returning *backend.ErrNotFound (not just any
// error) when nothing is stored, since gitCredentialStore and
// gitCredentialErase distinguish "genuinely absent" from "some other
// failure" via errors.As on that exact type.
func TestFakeBackendSatisfiesErrNotFoundContract(t *testing.T) {
	b := newFakeGitCredentialBackend()
	_, err := b.GetPassword("nope")
	var notFound *backend.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("got %v, want *backend.ErrNotFound", err)
	}
}
