//go:build darwin

package backend

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The OSStatus values this file needs as literals. secSuccessStatus and
// secItemNotFoundStatus (defined in passwords_app.go) mirror the cgo
// constants, so a test that used them on both sides of a comparison would
// only prove that a variable equals itself. These literals are the
// independent side: they are what Security.h actually documents, so a change
// to the mirrors is caught rather than followed.
const (
	errSecSuccessValue              = 0
	errSecItemNotFoundValue         = -25300
	errSecInteractionNotAllowed     = -25308 // locked keychain, non-interactive
	errSecInteractionNotAllowedName = "errSecInteractionNotAllowed"
)

// TestOSStatusMirrors checks the plain-int32 mirrors of the cgo constants
// against the documented Security.h values. Everything else in this file
// depends on them being right.
func TestOSStatusMirrors(t *testing.T) {
	t.Parallel()
	if secSuccessStatus != errSecSuccessValue {
		t.Errorf("secSuccessStatus = %d, want errSecSuccess (%d)", secSuccessStatus, errSecSuccessValue)
	}
	if secItemNotFoundStatus != errSecItemNotFoundValue {
		t.Errorf("secItemNotFoundStatus = %d, want errSecItemNotFound (%d)", secItemNotFoundStatus, errSecItemNotFoundValue)
	}
	if secInteractionNotAllowedStatus != errSecInteractionNotAllowed {
		t.Errorf("secInteractionNotAllowedStatus = %d, want %s (%d)",
			secInteractionNotAllowedStatus, errSecInteractionNotAllowedName, errSecInteractionNotAllowed)
	}
}

func TestIsRealFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		st   int32
		want bool
	}{
		{name: "success is not a failure", st: errSecSuccessValue, want: false},
		{name: "item not found is not a failure", st: errSecItemNotFoundValue, want: false},
		{name: errSecInteractionNotAllowedName + " is a failure", st: errSecInteractionNotAllowed, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isRealFailure(tc.st); got != tc.want {
				t.Errorf("isRealFailure(%d) = %v, want %v", tc.st, got, tc.want)
			}
		})
	}
}

// TestNotFoundInBothQueries exercises the classification logic that decides
// whether a NULL result from sec_copy_password/sec_copy_username is a
// definitive "not found" or a real failure that must not be reported as
// such. The two queries' statuses are independent (see the comment on
// notFoundInBothQueries): a real failure on either one must not be masked
// by the other query genuinely finding nothing.
func TestNotFoundInBothQueries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                  string
		stGeneric, stInternet int32
		want                  bool
	}{
		{"both not found", errSecItemNotFoundValue, errSecItemNotFoundValue, true},
		{"generic real failure, internet not found", errSecInteractionNotAllowed, errSecItemNotFoundValue, false},
		{"generic not found, internet real failure", errSecItemNotFoundValue, errSecInteractionNotAllowed, false},
		{"both real failure", errSecInteractionNotAllowed, errSecInteractionNotAllowed, false},
		{"generic success sentinel leaked through, internet not found", errSecSuccessValue, errSecItemNotFoundValue, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := notFoundInBothQueries(tc.stGeneric, tc.stInternet); got != tc.want {
				t.Errorf("notFoundInBothQueries(%d, %d) = %v, want %v", tc.stGeneric, tc.stInternet, got, tc.want)
			}
		})
	}
}

// TestClassifyPasswordsAppLookup pins the mapping onto the Backend error
// types the callers act on: only a definitive miss in both classes may be
// *ErrNotFound, because cmd/set.go reads that as "safe to overwrite".
func TestClassifyPasswordsAppLookup(t *testing.T) {
	t.Parallel()
	t.Run("both not found is ErrNotFound", func(t *testing.T) {
		t.Parallel()
		err := classifyPasswordsAppLookup("svc", errSecItemNotFoundValue, errSecItemNotFoundValue)
		var notFound *ErrNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("classifyPasswordsAppLookup() = %v (%T), want *ErrNotFound", err, err)
		}
	})

	t.Run("a real failure is ErrUnavailable", func(t *testing.T) {
		t.Parallel()
		err := classifyPasswordsAppLookup("svc", errSecInteractionNotAllowed, errSecItemNotFoundValue)
		var notFound *ErrNotFound
		if errors.As(err, &notFound) {
			t.Fatalf("classifyPasswordsAppLookup() = *ErrNotFound (%v); an unreadable credential must not look absent", err)
		}
		var unavailable *ErrUnavailable
		if !errors.As(err, &unavailable) {
			t.Fatalf("classifyPasswordsAppLookup() = %v (%T), want *ErrUnavailable", err, err)
		}
	})
}

// TestPasswordsApp_GetPassword_NotFound checks that a service which is
// genuinely absent is reported as *ErrNotFound.
//
// It is opt-in because it queries the *runner's own* default keychain list —
// real, uncontrolled I/O whose result depends on that keychain's state, and
// which would fail with errSecInteractionNotAllowed if it happened to be
// locked. Gating it matches the posture the far more controlled
// locked-keychain tests in keychain_test.go already use. The always-on
// coverage of the same logic is TestClassifyPasswordsAppLookup above.
//
// Note that this does not exercise the entitlement-restricted ambiguity from
// #20/#27 either: this process has no keychain-access entitlements at all, so
// it cannot distinguish "absent" from "present but denied" for any item on
// this backend.
func TestPasswordsApp_GetPassword_NotFound(t *testing.T) {
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to query the runner's real default keychain")
	}
	p := NewPasswordsApp()
	_, err := p.GetPassword("secret-issue30-does-not-exist-passwordsapp")
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("GetPassword() error = %v (%T), want *ErrNotFound", err, err)
	}
}

// TestQueriesRefuseKeychainUI checks the first of the two levers behind the
// #37 fix: that the single dictionary-construction path every SecItem* call
// in passwords_app.go goes through carries
// kSecUseAuthenticationUI = kSecUseAuthenticationUIFail.
//
// It asks CoreFoundation what is actually in the dictionary rather than
// re-stating the source, so removing the key from _no_ui_dict fails here.
// No keychain is touched, so unlike the live tests below this runs
// everywhere.
func TestQueriesRefuseKeychainUI(t *testing.T) {
	t.Parallel()
	if !queriesRefuseKeychainUI() {
		t.Error("queries built by _no_ui_dict do not set kSecUseAuthenticationUI=kSecUseAuthenticationUIFail; " +
			"a SecItem* call on the Data Protection keychain is free to block on an unlock dialog again (#37)")
	}
}

// TestRefuseKeychainUIDisablesLegacyKeychainUI checks the second lever:
// SecKeychainSetUserInteractionAllowed(FALSE), which is the only thing that
// covers the legacy file-backed keychain — the one this backend actually
// writes to, and the source of the #44 ACL dialog. SecItem.h is explicit
// that the dictionary key above does not reach legacy items, so the two are
// not interchangeable and both are checked.
//
// This reads back process state from the Security framework; it opens no
// keychain and stores nothing.
//
// Deliberately not parallel and deliberately not restored: it leaves keychain
// UI refused for every test that runs after it in this binary. That is the
// state production runs in, and the state the other tests here want, so the
// leak is harmless — but it is a leak, and a future test that needs the
// dialog back will have to set it back itself.
func TestRefuseKeychainUIDisablesLegacyKeychainUI(t *testing.T) {
	refuseKeychainUI()
	allowed, answered := keychainUIAllowed()
	if !answered {
		t.Skip("SecKeychainGetUserInteractionAllowed did not answer on this host")
	}
	if allowed {
		t.Error("keychain user interaction is still allowed after refuseKeychainUI(); " +
			"a legacy-keychain SecItem* call can still block on an unlock or ACL dialog (#37, #44)")
	}
}

// TestEveryKeychainEntryPointRefusesUI is the guard against the way this fix
// is most likely to be undone: not by deleting refuseKeychainUI, but by
// adding a sixth PasswordsApp method that reaches the Security framework and
// forgetting to call it. That method would be unbounded again, silently, and
// no behavioural test would notice unless it happened to run against a
// locked keychain.
//
// So this reads passwords_app.go itself and requires every *PasswordsApp
// method whose body calls into the C preamble to call refuseKeychainUI()
// first. It is a structural assertion because the property being asserted is
// structural: the underlying framework switch is process-global and set
// once, so no runtime state distinguishes "this method called it" from "some
// earlier method did".
func TestEveryKeychainEntryPointRefusesUI(t *testing.T) {
	t.Parallel()

	const src = "passwords_app.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}

	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || !isPasswordsAppReceiver(fn.Recv) {
			continue
		}
		if !callsSecurityFramework(fn.Body) {
			continue
		}
		checked++
		if !refusesUIFirst(fn.Body) {
			t.Errorf("(*PasswordsApp).%s reaches the Security framework but does not call refuseKeychainUI() first; "+
				"that call is unbounded and can block on a keychain dialog forever (#37)", fn.Name.Name)
		}
	}

	// A refactor that renamed the receiver or moved the C calls behind a
	// Go-side helper would otherwise leave this test passing while checking
	// nothing at all.
	if checked < 5 {
		t.Errorf("found only %d *PasswordsApp methods calling into the Security framework, want at least 5 "+
			"(GetPassword, GetUsername, Add, Delete, List); this test is no longer looking at what it thinks it is", checked)
	}
}

func isPasswordsAppReceiver(recv *ast.FieldList) bool {
	if len(recv.List) != 1 {
		return false
	}
	star, ok := recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "PasswordsApp"
}

// callsSecurityFramework reports whether body contains a call to one of the
// C helpers in this file's preamble that reaches SecItem*/SecKeychain*. The
// sec_ prefix is the naming convention every such helper follows; C.CString
// and C.free are deliberately not matched, because they are plain libc and
// block on nothing.
func callsSecurityFramework(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "C" {
			return true
		}
		if strings.HasPrefix(sel.Sel.Name, "sec_") {
			found = true
		}
		return true
	})
	return found
}

func refusesUIFirst(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	expr, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "refuseKeychainUI"
}

// TestPasswordsApp_RoundTrip_Live is the regression guard for the other half
// of the #37 change: refusing UI must not break the calls that were working.
// kSecUseAuthenticationUI is an extra key in every query and attribute
// dictionary, including the one handed to SecItemAdd, and an argument macOS
// rejected would turn every operation into errSecParam. Nothing else in the
// suite would catch that, because nothing else calls the real framework.
//
// Opt-in for the same reason as TestPasswordsApp_GetPassword_NotFound: it
// writes to, reads from and deletes from the runner's own default keychain.
func TestPasswordsApp_RoundTrip_Live(t *testing.T) {
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to write to the runner's real default keychain")
	}
	p := NewPasswordsApp()
	service := fmt.Sprintf("secret-issue37-roundtrip-%d", os.Getpid())

	if err := p.Add(service, "issue37", "issue37-password"); err != nil {
		t.Fatalf("Add() error = %v; refusing keychain UI must not break a working write", err)
	}
	t.Cleanup(func() {
		if err := p.Delete(service); err != nil {
			var notFound *ErrNotFound
			if !errors.As(err, &notFound) {
				t.Errorf("cleanup Delete(%q) error = %v; the test item may still be in the keychain", service, err)
			}
		}
		if _, err := p.GetPassword(service); err == nil {
			t.Errorf("cleanup left %q readable in the keychain", service)
		}
	})

	if got, err := p.GetPassword(service); err != nil || got != "issue37-password" {
		t.Errorf("GetPassword() = %q, %v; want %q, <nil>", got, err, "issue37-password")
	}
	if got, err := p.GetUsername(service); err != nil || got != "issue37" {
		t.Errorf("GetUsername() = %q, %v; want %q, <nil>", got, err, "issue37")
	}
	services, err := p.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !slices.Contains(services, service) {
		t.Errorf("List() did not contain %q", service)
	}
}

// TestClassifyPasswordsAppDelete is the regression guard for the defect this
// PR's own UI refusal made reachable: sec_delete_item kept one shared
// OSStatus that the internet-class delete overwrote unconditionally, so a
// generic-class delete refused with errSecInteractionNotAllowed was reported
// as the internet class's errSecItemNotFound — i.e. *ErrNotFound.
//
// That is not a cosmetic misclassification. cmd/gitcredential.go suppresses
// *ErrNotFound from Delete entirely, so `git credential reject` returned
// success having erased nothing, and git then retried forever against a
// credential it believed it had removed. Same bug class as #30 and #36, on
// the shipped macOS default backend.
//
// The first case below is the exact status pair that path produces.
func TestClassifyPasswordsAppDelete(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                  string
		stGeneric, stInternet int32
		wantNotFound          bool
	}{
		{
			// The #44 shape: the ACL does not cover this binary, so the
			// generic delete is refused rather than shown a dialog, and the
			// internet delete matches no kSecAttrServer item.
			name:      "generic refused, internet not found is not a definite absence",
			stGeneric: errSecInteractionNotAllowed, stInternet: errSecItemNotFoundValue,
			wantNotFound: false,
		},
		{
			name:      "generic not found, internet refused is not a definite absence",
			stGeneric: errSecItemNotFoundValue, stInternet: errSecInteractionNotAllowed,
			wantNotFound: false,
		},
		{
			name:      "both refused is not a definite absence",
			stGeneric: errSecInteractionNotAllowed, stInternet: errSecInteractionNotAllowed,
			wantNotFound: false,
		},
		{
			name:      "both not found is a definite absence",
			stGeneric: errSecItemNotFoundValue, stInternet: errSecItemNotFoundValue,
			wantNotFound: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := classifyPasswordsAppDelete("github.com", tc.stGeneric, tc.stInternet)
			var notFound *ErrNotFound
			gotNotFound := errors.As(err, &notFound)
			if gotNotFound != tc.wantNotFound {
				t.Fatalf("classifyPasswordsAppDelete(%d, %d) = %v (%T); ErrNotFound=%v, want %v",
					tc.stGeneric, tc.stInternet, err, err, gotNotFound, tc.wantNotFound)
			}
			if tc.wantNotFound {
				return
			}
			var unavailable *ErrUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("classifyPasswordsAppDelete(%d, %d) = %v (%T), want *ErrUnavailable",
					tc.stGeneric, tc.stInternet, err, err)
			}
		})
	}
}

// TestPasswordsAppWriteAndListErrorsAreTyped pins the convention Keychain.Add
// and Keychain.List already follow and this backend had drifted from: a
// failure to write or to enumerate is *ErrUnavailable, never an untyped
// error. Nothing branches on it today; the Keychain/PasswordsApp divergence
// in #36 also had no consumer, right up until it cost a credential.
//
// Driving the real Add/List would need a keychain that fails on demand, which
// there is no way to arrange here, so this checks the classification these
// methods construct — the part that was wrong — via the same helpers they use.
func TestPasswordsAppWriteAndListErrorsAreTyped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{"delete", classifyPasswordsAppDelete("svc", errSecInteractionNotAllowed, errSecInteractionNotAllowed)},
		{"read", classifyPasswordsAppLookup("svc", errSecInteractionNotAllowed, errSecItemNotFoundValue)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var unavailable *ErrUnavailable
			if !errors.As(tc.err, &unavailable) {
				t.Errorf("%s error = %v (%T), want *ErrUnavailable", tc.name, tc.err, tc.err)
			}
		})
	}
}

// TestInteractionRefusedNoteExplainsTheStatusThisPackageCreates checks that
// the one failure this file deliberately manufactures carries a cause and a
// remedy rather than a bare number.
//
// Refusing keychain UI converts "show an unlock dialog" into
// errSecInteractionNotAllowed, so a user with a locked keychain who used to
// answer a dialog and get their credential now gets an error instead. If that
// error says only "Security error (generic query: -25308...)", the change has
// removed their only route to understanding what happened — `secret` is the
// shipped macOS default, and gitCredentialGet discards the error entirely, so
// this string is the only place the cause can surface.
func TestInteractionRefusedNoteExplainsTheStatusThisPackageCreates(t *testing.T) {
	t.Parallel()

	if note := interactionRefusedNote(errSecItemNotFoundValue, errSecSuccessValue); note != "" {
		t.Errorf("interactionRefusedNote(not-found, success) = %q, want empty: "+
			"asserting a cause for a status it does not describe is the mistake "+
			"keychainUnavailableReason exists to record", note)
	}

	err := classifyPasswordsAppLookup("github.com", errSecInteractionNotAllowed, errSecInteractionNotAllowed)
	msg := err.Error()
	for _, want := range []string{"keychain dialog", "locked", "access control"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error for errSecInteractionNotAllowed = %q, want it to mention %q", msg, want)
		}
	}
	if !strings.Contains(msg, strconv.Itoa(errSecInteractionNotAllowed)) {
		t.Errorf("error for errSecInteractionNotAllowed = %q, want it to still carry the raw status %d",
			msg, errSecInteractionNotAllowed)
	}
}

// TestRefuseKeychainUINoteReportsALatchedFailure covers the sync.Once latch:
// if SecKeychainSetUserInteractionAllowed fails, it is never retried for the
// life of the process, and without this note a hang caused by the lever
// having silently failed would look exactly like the residual risk this
// design knowingly accepts (a wedged securityd).
func TestRefuseKeychainUINoteReportsALatchedFailure(t *testing.T) {
	// Not parallel: it swaps a package-level variable.
	saved := refuseKeychainUIStatus
	t.Cleanup(func() { refuseKeychainUIStatus = saved })

	refuseKeychainUIStatus = secSuccessStatus
	if note := refuseKeychainUINote(); note != "" {
		t.Errorf("refuseKeychainUINote() = %q on success, want empty", note)
	}

	refuseKeychainUIStatus = errSecInteractionNotAllowed
	note := refuseKeychainUINote()
	if !strings.Contains(note, "SecKeychainSetUserInteractionAllowed") {
		t.Errorf("refuseKeychainUINote() = %q, want it to name the lever that failed", note)
	}
	if !strings.Contains(note, strconv.Itoa(errSecInteractionNotAllowed)) {
		t.Errorf("refuseKeychainUINote() = %q, want it to carry the status %d", note, errSecInteractionNotAllowed)
	}
}
