package cmd

import (
	"strings"
	"testing"
)

func TestErrUnrecognisedBackend_Typo(t *testing.T) {
	err := errUnrecognisedBackend("typo", "darwin", []string{"keychain", "passwords-app"})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"typo"`) {
		t.Errorf("error %q does not mention the offending value", msg)
	}
	if !strings.Contains(msg, "keychain, passwords-app") {
		t.Errorf("error %q does not list the values valid on this platform", msg)
	}
	if strings.Contains(msg, "only available on") {
		t.Errorf("error %q should not claim a plain typo is valid elsewhere: %q", msg, msg)
	}
}

func TestErrUnrecognisedBackend_ValidElsewhere(t *testing.T) {
	// "secret-service" is a real backend name — just not one darwin
	// accepts. Design question 2 asks for this to be distinguishable from
	// a typo in the error message.
	err := errUnrecognisedBackend("secret-service", "darwin", []string{"keychain", "passwords-app"})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "only available on linux") {
		t.Errorf("error %q does not explain that this name is valid on a different platform", msg)
	}
	if !strings.Contains(msg, "keychain, passwords-app") {
		t.Errorf("error %q does not list the values valid on this platform", msg)
	}
}

func TestBackendEnvValue_TrimsSurroundingWhitespace(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"unset", "", ""},
		{"trailing space", "keychain ", "keychain"},
		{"leading space", " keychain", "keychain"},
		{"tab and newline", "\tkeychain\n", "keychain"},
		{"whitespace only", " \t\r\n ", ""},
		{"interior whitespace kept", "key chain", "key chain"},
		{"case kept", "Keychain", "Keychain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECRET_BACKEND", tc.in)
			if got := backendEnvValue(); got != tc.want {
				t.Errorf("backendEnvValue() with SECRET_BACKEND=%q = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestErrUnrecognisedBackend_ShowsInteriorWhitespaceEscaped(t *testing.T) {
	msg := errUnrecognisedBackend("key\tchain", "darwin", []string{"keychain"}).Error()
	if !strings.Contains(msg, `"key\tchain"`) {
		t.Errorf("error %q does not show the tab escaped", msg)
	}
}
