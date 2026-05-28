//go:build darwin

package backend

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

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
	cmd := exec.Command("/usr/bin/security", "show-keychain-info", k.keychainPath)
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
		return "", &ErrNotFound{Service: service}
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
		return "", &ErrNotFound{Service: service}
	}
	return strings.TrimRight(output, "\n"), nil
}

func (k *Keychain) Add(service, account, password string) error {
	cmd := exec.Command("/usr/bin/security", "add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", "/usr/bin/security",
		k.keychainPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add secret for '%s': %s", service, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *Keychain) Delete(service string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, k.keychainPath)
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Run(); err == nil {
		return nil
	}

	cmd = exec.Command("/usr/bin/security", "delete-internet-password", "-s", service, k.keychainPath)
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

func (k *Keychain) findPassword(service string, passwordOnly bool) (string, error) {
	var flag string
	if passwordOnly {
		flag = "-w"
	} else {
		flag = "-g"
	}

	// Try generic password first
	cmd := exec.Command("/usr/bin/security", "find-generic-password", flag, "-s", service, k.keychainPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Run(); err == nil {
		return stdout.String(), nil
	}

	// Fall back to internet password
	stdout.Reset()
	cmd = exec.Command("/usr/bin/security", "find-internet-password", flag, "-s", service, k.keychainPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
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
