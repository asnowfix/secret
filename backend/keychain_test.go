//go:build darwin

package backend

import (
	"reflect"
	"testing"
)

func TestParseKeychainDumpServices(t *testing.T) {
	// Trimmed sample of real `security dump-keychain` output: a generic
	// password entry (via the "svce" attribute) and an internet password
	// entry (via the "srvr" attribute), plus a duplicate to test dedup.
	dump := `keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="com.apple.assistant"
    "acct"<blob>="someone"
    "svce"<blob>="com.apple.assistant"
keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "acct"<blob>="someone@example.com"
    "srvr"<blob>="example.com"
keychain: "/Users/fix/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "svce"<blob>="com.apple.assistant"
`

	got := parseKeychainDumpServices(dump)
	want := []string{"com.apple.assistant", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeychainDumpServices() = %v, want %v", got, want)
	}
}

func TestParseKeychainDumpServices_HexEncoded(t *testing.T) {
	// "abc" hex-encoded, matching how dump-keychain renders non-ASCII values.
	dump := `class: "genp"
attributes:
    "svce"<blob>=0x616263  "abc"
`
	got := parseKeychainDumpServices(dump)
	want := []string{"abc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeychainDumpServices() = %v, want %v", got, want)
	}
}

func TestParseKeychainDumpServices_Empty(t *testing.T) {
	got := parseKeychainDumpServices("")
	if len(got) != 0 {
		t.Errorf("parseKeychainDumpServices(\"\") = %v, want empty", got)
	}
}
