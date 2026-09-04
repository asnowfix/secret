//go:build darwin

package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// securityBinary is the path to the security CLI. It is a var, not a
// const, so tests can point it at a stand-in binary instead of the real
// /usr/bin/security.
var securityBinary = "/usr/bin/security"

// securityCommandTimeout bounds every call to securityBinary. This path is
// meant to be entirely non-interactive, but /usr/bin/security itself does
// not honor that on its own: against a locked keychain it can hand off to
// the system's interactive keychain-unlock UI, and on a headless session
// (e.g. a CI runner with no logged-in GUI user to answer that prompt) that
// hand-off blocks forever with no output. This was confirmed to not be a
// case of Go's exec.Cmd inheriting/blocking on stdin — cmd.Stdin is left
// nil throughout this file, and since Go 1.20 a nil Stdin makes the child
// read from os.DevNull (immediate EOF), not from the parent's terminal —
// so the fix has to bound the call itself, not stdin. It is a var, not a
// const, so tests can shrink it instead of waiting out the real value.
var securityCommandTimeout = 10 * time.Second

// errSecurityTimeout is runSecurityFind's sentinel for "the security
// process did not finish within securityCommandTimeout". It must never be
// treated as errItemNotFound: an unresponsive keychain is not a confirmed
// absence, and collapsing the two would recreate the exact silent-overwrite
// bug (issue #30) this file's error classification exists to prevent.
var errSecurityTimeout = errors.New("security command did not respond within the timeout")

// Keychain implements Backend using the macOS /usr/bin/security CLI.
type Keychain struct {
	keychainPath string
}

func NewKeychain() *Keychain {
	home, _ := os.UserHomeDir()
	return &Keychain{
		keychainPath: filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
	}
}

func (k *Keychain) IsAvailable() error {
	ctx, cancel := context.WithTimeout(context.Background(), securityCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityBinary, "show-keychain-info", k.keychainPath)
	cmd.Stdin = nil
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		return &ErrUnavailable{Reason: "keychain locked — cannot retrieve secrets non-interactively"}
	}
	return nil
}

var acctRegexp = regexp.MustCompile(`^\s+"acct"<[^>]*>=(?:"([^"]*)"|0x([0-9A-Fa-f]+))`)

func (k *Keychain) GetUsername(service string) (string, error) {
	output, err := k.findPassword(service, false)
	if err != nil {
		if errors.Is(err, errItemNotFound) {
			return "", &ErrNotFound{Service: service}
		}
		if errors.Is(err, errSecurityTimeout) {
			return "", &ErrUnavailable{Reason: keychainTimeoutReason(err)}
		}
		return "", &ErrUnavailable{Reason: fmt.Sprintf("could not read keychain item for %q: %v", service, err)}
	}

	for _, line := range strings.Split(output, "\n") {
		if m := acctRegexp.FindStringSubmatch(line); m != nil {
			if m[1] != "" {
				return m[1], nil
			}
			if m[2] != "" {
				decoded, err := hexDecode(m[2])
				if err == nil {
					return decoded, nil
				}
			}
		}
	}
	return "", &ErrNotFound{Service: service}
}

func (k *Keychain) GetPassword(service string) (string, error) {
	output, err := k.findPassword(service, true)
	if err != nil {
		if errors.Is(err, errItemNotFound) {
			return "", &ErrNotFound{Service: service}
		}
		if errors.Is(err, errSecurityTimeout) {
			return "", &ErrUnavailable{Reason: keychainTimeoutReason(err)}
		}
		return "", &ErrUnavailable{Reason: fmt.Sprintf("could not read keychain item for %q: %v", service, err)}
	}
	return strings.TrimRight(output, "\n"), nil
}

// keychainTimeoutReason builds the *ErrUnavailable diagnostic for a
// security invocation that timed out, naming the likely cause (a locked
// keychain with no agent able to answer an unlock prompt) rather than a
// generic failure message.
func keychainTimeoutReason(err error) string {
	return fmt.Sprintf("keychain unavailable: security command did not respond, possibly locked with no agent to answer (%v)", err)
}

func (k *Keychain) Add(service, account, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), securityCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityBinary, "add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", securityBinary,
		k.keychainPath,
	)
	cmd.Stdin = nil
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add secret for '%s': %s", service, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *Keychain) Delete(service string) error {
	ctx, cancel := context.WithTimeout(context.Background(), securityCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityBinary, "delete-generic-password", "-s", service, k.keychainPath)
	cmd.Stdin = nil
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Run(); err == nil {
		return nil
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), securityCommandTimeout)
	defer cancel2()
	cmd = exec.CommandContext(ctx2, securityBinary, "delete-internet-password", "-s", service, k.keychainPath)
	cmd.Stdin = nil
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		return &ErrNotFound{Service: service}
	}
	return nil
}

func (k *Keychain) Edit() error {
	return exec.Command("open", "-b", "com.apple.keychainaccess").Start()
}

// errItemNotFound is findPassword's internal sentinel for a definitive "no
// such item", i.e. /usr/bin/security exiting with secItemNotFoundExitCode.
// Any other failure (locked keychain, missing binary, unexpected exit code)
// is returned as its own error instead, so GetPassword/GetUsername can tell
// "absent" apart from "could not determine" rather than collapsing both into
// *ErrNotFound.
var errItemNotFound = errors.New("keychain item not found")

// secItemNotFoundExitCode is the Unix exit code /usr/bin/security uses to
// report errSecItemNotFound (OSStatus -25300). An OSStatus becomes a process
// exit code via its low byte (-25300 & 0xFF == 44); verified by hand against
// a scratch keychain (see PR description) rather than assumed.
const secItemNotFoundExitCode = 44

// runSecurityFind runs securityBinary with the given arguments, bounded by
// securityCommandTimeout, and classifies the result: success returns
// stdout; a definitive "item not found" exit returns errItemNotFound; a
// timeout returns errSecurityTimeout; anything else (locked keychain,
// missing/non-executable binary, unexpected exit code) returns an error
// carrying whatever diagnostic security produced, instead of being folded
// into "not found".
//
// The child is bounded via exec.CommandContext rather than a bare
// exec.Command: on timeout, the context's default Cancel (os.Process.Kill)
// terminates the child and the in-flight cmd.Run/Wait call reaps it, so no
// orphan process is left behind — the exact cleanup CI had to do by hand
// for the unbounded call this replaces. cmd.Stdin is left nil, i.e.
// /dev/null, so the child can never block reading from an inherited
// terminal either.
func runSecurityFind(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityBinary, args...)
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%w: security %s against %s", errSecurityTimeout, args[0], securityCommandTimeout)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == secItemNotFoundExitCode {
			return "", errItemNotFound
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			// security sometimes exits non-zero with no stderr at all — e.g.
			// a locked keychain queried non-interactively exits 152 with no
			// message. Fall back to the process error so the caller still
			// gets a real diagnostic instead of silence.
			msg = err.Error()
		}
		return "", fmt.Errorf("security %s: %s", args[0], msg)
	}
	return stdout.String(), nil
}

func (k *Keychain) findPassword(service string, passwordOnly bool) (string, error) {
	var flag string
	if passwordOnly {
		flag = "-w"
	} else {
		flag = "-g"
	}

	// Try generic password first. A real failure here (not a "not found")
	// means we cannot determine whether the item exists at all, so return
	// immediately rather than masking it with an internet-password attempt.
	out, err := runSecurityFind("find-generic-password", flag, "-s", service, k.keychainPath)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, errItemNotFound) {
		return "", err
	}

	// Fall back to internet password.
	return runSecurityFind("find-internet-password", flag, "-s", service, k.keychainPath)
}

func hexDecode(s string) (string, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				val = val*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				val = val*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val = val*16 + (c - 'A' + 10)
			default:
				return "", fmt.Errorf("invalid hex char: %c", c)
			}
		}
		b[i/2] = val
	}
	return string(b), nil
}
