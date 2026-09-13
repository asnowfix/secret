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
