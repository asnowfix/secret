//go:build darwin

package backend

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Refusing keychain UI (issue #37)
//
// Every SecItem* call below is synchronous cgo. Unlike the /usr/bin/security
// subprocess (keychain.go) and the D-Bus round trips (libsecret.go), there is
// nothing here a context can cancel: no child process to kill, and the
// calling goroutine is pinned to its OS thread for the duration. So the only
// way to bound these calls is to remove the reason they block, which in every
// reported case is a GUI dialog nobody is there to answer — a keychain-unlock
// prompt, or the ACL authorization dialog raised when the reading executable
// is not the one that created the item (issue #44).
//
// macOS needs both levers below, because it has two keychain implementations
// and each ignores the other's:
//
//   1. kSecUseAuthenticationUI = kSecUseAuthenticationUIFail in every query
//      and attribute dictionary. This covers the Data Protection keychain —
//      iCloud-synced items, i.e. exactly what Passwords.app manages and what
//      kSecAttrSynchronizableAny brings into these queries. SecItem.h is
//      explicit that this is all it covers: "on macOS, this attribute only
//      applies to items stored in the Data Protection keychain. Legacy
//      keychain items will still activate UI if needed."
//
//   2. SecKeychainSetUserInteractionAllowed(FALSE). This covers the legacy
//      file-backed keychain (login.keychain-db) — which is where
//      sec_add_generic_password actually writes, and where the #44 ACL dialog
//      comes from. It is the only lever for that path.
//
// Both make the call return errSecInteractionNotAllowed (-25308) instead of
// waiting. classifyPasswordsAppLookup and isRealFailure already route that to
// *ErrUnavailable, so the caller gets an actionable error rather than a hang.
//
// Apple's suggested replacement for kSecUseAuthenticationUIFail is
// kSecUseAuthenticationContext with LAContext.interactionNotAllowed, which
// governs LocalAuthentication (Touch ID / password re-auth) and not the
// keychain-unlock or ACL dialogs that hang here; and there is no replacement
// at all for SecKeychainSetUserInteractionAllowed. Both are therefore used
// deliberately in their deprecated form, with the warning suppressed over the
// smallest region that needs it.
// ---------------------------------------------------------------------------

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// sec_refuse_user_interaction turns off keychain UI for this process, so that
// a legacy-keychain call which would otherwise put up an unlock or ACL dialog
// fails with errSecInteractionNotAllowed instead. Process-global by
// construction — there is no per-call form of it — and never restored: see
// refuseKeychainUI on the Go side for why that is the intended scope here.
static OSStatus sec_refuse_user_interaction(void) {
	return SecKeychainSetUserInteractionAllowed(FALSE);
}

// sec_user_interaction_allowed reports the process-global state above, so a
// test can assert it was actually applied rather than assume it.
static OSStatus sec_user_interaction_allowed(int *allowed) {
	Boolean state = TRUE;
	OSStatus st = SecKeychainGetUserInteractionAllowed(&state);
	*allowed = state ? 1 : 0;
	return st;
}

// _no_ui_dict builds the CFDictionary for a SecItem* call from n key/value
// pairs, always appending kSecUseAuthenticationUI = kSecUseAuthenticationUIFail.
//
// Every dictionary in this file is created here rather than by calling
// CFDictionaryCreate directly, so that "refuse UI" cannot be forgotten at one
// of the seven call sites. That is not hypothetical tidiness: the defect this
// function exists to fix was precisely that none of them set it.
//
// Every caller passes a literal n of 5 or fewer, so the NULL return for an
// oversized n is unreachable today; it is there so that a future caller that
// does exceed the buffer fails on a NULL dictionary rather than silently
// smashing the stack.
#define _NO_UI_DICT_MAX 8
static CFDictionaryRef _no_ui_dict(const void **k, const void **v, CFIndex n) {
	const void *ks[_NO_UI_DICT_MAX + 1];
	const void *vs[_NO_UI_DICT_MAX + 1];
	if (n > _NO_UI_DICT_MAX) return NULL;
	for (CFIndex i = 0; i < n; i++) { ks[i] = k[i]; vs[i] = v[i]; }
	ks[n] = kSecUseAuthenticationUI;
	vs[n] = kSecUseAuthenticationUIFail;
	return CFDictionaryCreate(NULL, ks, vs, n + 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

// sec_dict_refuses_ui reports whether a dictionary built by _no_ui_dict
// carries the refuse-UI key. It exists for the test: cgo constants are not
// reachable from _test.go files, so this is how Go-side tests check the one
// construction path every query goes through.
static int sec_dict_refuses_ui(void) {
	const void *k[] = {kSecClass};
	const void *v[] = {kSecClassGenericPassword};
	CFDictionaryRef q = _no_ui_dict(k, v, 1);
	if (!q) return 0;
	CFTypeRef ui = CFDictionaryGetValue(q, kSecUseAuthenticationUI);
	int ok = (ui != NULL) && CFEqual(ui, kSecUseAuthenticationUIFail);
	CFRelease(q);
	return ok;
}

#pragma clang diagnostic pop

// _cfdata_to_cstr copies CFDataRef bytes into a malloc'd, null-terminated string.
static char* _cfdata_to_cstr(CFDataRef d) {
	CFIndex n = CFDataGetLength(d);
	char *b = malloc(n + 1);
	if (!b) return NULL;
	CFDataGetBytes(d, CFRangeMake(0, n), (UInt8*)b);
	b[n] = '\0';
	return b;
}

// _cfstring_to_cstr converts a CFStringRef to a malloc'd UTF-8 C string.
static char* _cfstring_to_cstr(CFStringRef s) {
	CFIndex maxLen = CFStringGetMaximumSizeForEncoding(
		CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *b = malloc(maxLen);
	if (!b) return NULL;
	if (!CFStringGetCString(s, b, maxLen, kCFStringEncodingUTF8)) {
		free(b);
		return NULL;
	}
	return b;
}

// sec_copy_password returns the password for name as a malloc'd string (caller must free),
// or NULL if not found. Tries kSecClassGenericPassword then kSecClassInternetPassword.
// kSecAttrSynchronizableAny is included so iCloud-synced Passwords.app items are searched.
//
// The two queries' OSStatus results are reported separately via stGeneric/
// stInternet, rather than collapsed into one value: if the generic query
// hits a real failure (e.g. errSecInteractionNotAllowed on a locked
// keychain) but the internet query simply finds nothing
// (errSecItemNotFound), a single shared status would report the latter and
// hide the former, making a "could not determine" failure look like a
// definitive "not found" to the caller.
static char* sec_copy_password(const char *name, OSStatus *stGeneric, OSStatus *stInternet) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	*stGeneric = errSecItemNotFound;
	*stInternet = errSecItemNotFound;

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnData, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 5);
		CFTypeRef r = NULL;
		*stGeneric = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stGeneric == errSecSuccess && r) {
			char *out = _cfdata_to_cstr((CFDataRef)r);
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnData, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 5);
		CFTypeRef r = NULL;
		*stInternet = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stInternet == errSecSuccess && r) {
			char *out = _cfdata_to_cstr((CFDataRef)r);
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	CFRelease(n);
	return NULL;
}

// sec_copy_username returns the account name for name as a malloc'd string (caller must free),
// or NULL if not found. Tries kSecClassGenericPassword then kSecClassInternetPassword.
// kSecAttrSynchronizableAny is included so iCloud-synced Passwords.app items are searched.
//
// See sec_copy_password for why stGeneric/stInternet are reported separately
// instead of being collapsed into one shared status.
static char* sec_copy_username(const char *name, OSStatus *stGeneric, OSStatus *stInternet) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	*stGeneric = errSecItemNotFound;
	*stInternet = errSecItemNotFound;

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 5);
		CFTypeRef r = NULL;
		*stGeneric = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stGeneric == errSecSuccess && r) {
			CFStringRef acct = CFDictionaryGetValue((CFDictionaryRef)r, kSecAttrAccount);
			char *out = acct ? _cfstring_to_cstr(acct) : NULL;
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 5);
		CFTypeRef r = NULL;
		*stInternet = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stInternet == errSecSuccess && r) {
			CFStringRef acct = CFDictionaryGetValue((CFDictionaryRef)r, kSecAttrAccount);
			char *out = acct ? _cfstring_to_cstr(acct) : NULL;
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	CFRelease(n);
	return NULL;
}

// sec_add_generic_password adds a kSecClassGenericPassword item.
static OSStatus sec_add_generic_password(const char *service, const char *account, const char *password) {
	CFStringRef svc  = CFStringCreateWithCString(NULL, service,  kCFStringEncodingUTF8);
	CFStringRef acct = CFStringCreateWithCString(NULL, account,  kCFStringEncodingUTF8);
	CFDataRef   data = CFDataCreate(NULL, (const UInt8*)password, strlen(password));
	const void *k[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData};
	const void *v[] = {kSecClassGenericPassword, svc, acct, data};
	CFDictionaryRef attrs = _no_ui_dict(k, v, 4);
	OSStatus st = SecItemAdd(attrs, NULL);
	CFRelease(attrs); CFRelease(data); CFRelease(acct); CFRelease(svc);
	return st;
}

// sec_copy_all_services returns all service/server names as a "\n"-joined,
// malloc'd C string (caller must free), or NULL if none were found. Searches
// both kSecClassGenericPassword and kSecClassInternetPassword, including
// iCloud-synced Passwords.app items.
//
// The two queries are independent, so their OSStatus results are reported
// separately via stGeneric/stInternet rather than collapsed into one value:
// the caller needs to be able to tell a genuine "no items" (errSecItemNotFound
// from both) apart from macOS denying access to one or both keychains, and
// to decide what to do when the two queries disagree.
static char* sec_copy_all_services(OSStatus *stGeneric, OSStatus *stInternet) {
	CFMutableStringRef out = CFStringCreateMutable(NULL, 0);
	int found = 0;

	{
		const void *k[] = {kSecClass, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, kCFBooleanTrue, kSecMatchLimitAll, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 4);
		CFTypeRef r = NULL;
		*stGeneric = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stGeneric == errSecSuccess && r) {
			CFArrayRef arr = (CFArrayRef)r;
			CFIndex n = CFArrayGetCount(arr);
			for (CFIndex i = 0; i < n; i++) {
				CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(arr, i);
				CFStringRef svc = CFDictionaryGetValue(item, kSecAttrService);
				if (svc) {
					if (found) CFStringAppend(out, CFSTR("\n"));
					CFStringAppend(out, svc);
					found = 1;
				}
			}
			CFRelease(r);
		}
	}

	{
		const void *k[] = {kSecClass, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, kCFBooleanTrue, kSecMatchLimitAll, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 4);
		CFTypeRef r = NULL;
		*stInternet = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*stInternet == errSecSuccess && r) {
			CFArrayRef arr = (CFArrayRef)r;
			CFIndex n = CFArrayGetCount(arr);
			for (CFIndex i = 0; i < n; i++) {
				CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(arr, i);
				CFStringRef svc = CFDictionaryGetValue(item, kSecAttrServer);
				if (svc) {
					if (found) CFStringAppend(out, CFSTR("\n"));
					CFStringAppend(out, svc);
					found = 1;
				}
			}
			CFRelease(r);
		}
	}

	if (!found) {
		CFRelease(out);
		return NULL;
	}
	char *result = _cfstring_to_cstr(out);
	CFRelease(out);
	return result;
}

// sec_delete_item deletes an item by service name.
// Tries kSecClassGenericPassword then kSecClassInternetPassword.
// kSecAttrSynchronizableAny ensures iCloud-synced items can be deleted too.
static OSStatus sec_delete_item(const char *name) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	OSStatus st;

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 3);
		st = SecItemDelete(q);
		CFRelease(q);
		if (st == errSecSuccess) { CFRelease(n); return st; }
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 3);
		st = SecItemDelete(q);
		CFRelease(q);
	}

	CFRelease(n);
	return st;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unsafe"
)

// PasswordsApp implements Backend using the Security framework directly via cgo.
// It searches the default keychain list (including iCloud Keychain) so credentials
// managed by Passwords.app on macOS 15+ are visible alongside login keychain items.
type PasswordsApp struct{}

func NewPasswordsApp() *PasswordsApp { return &PasswordsApp{} }

// refuseKeychainUIOnce guards the one-time, process-global
// SecKeychainSetUserInteractionAllowed(FALSE) that stops legacy-keychain
// calls from putting up an unlock or ACL dialog (issue #37; see the C
// preamble for why this and kSecUseAuthenticationUIFail are both needed).
var refuseKeychainUIOnce sync.Once

// refuseKeychainUI turns off keychain UI for this process. Every method that
// reaches the Security framework calls it first, rather than doing it in
// NewPasswordsApp, so that it holds for a PasswordsApp built any other way
// (tests construct one directly) and so the invariant lives next to the calls
// that depend on it.
//
// Three properties are deliberate and worth stating plainly, because they are
// what a reviewer would otherwise have to reverse-engineer:
//
//   - It is process-global. The Security framework offers no per-call form.
//     For this project that scope is the intent rather than a compromise:
//     secret and git-credential-secret are non-interactive credential tools,
//     run from shells, git, cron and CI, and a modal keychain dialog in any
//     of those contexts is the defect, not a feature.
//   - It is never restored. There is no point in the CLI's life where it
//     would want the dialog back; restoring it around each call would also
//     race with any concurrent caller and reopen the hole for the duration.
//   - Its failure is deliberately ignored. If the call fails, the worst case
//     is exactly today's behaviour on the legacy path, and the
//     kSecUseAuthenticationUIFail key still covers the Data Protection path;
//     refusing to run at all would be a strictly worse trade.
func refuseKeychainUI() {
	refuseKeychainUIOnce.Do(func() { C.sec_refuse_user_interaction() })
}

// keychainUIAllowed reports the process-global keychain-UI state that
// refuseKeychainUI turns off, and whether the framework answered at all.
//
// queriesRefuseKeychainUI reports whether _no_ui_dict — the single
// construction path behind every SecItem* call in this file — sets the
// refuse-UI key.
//
// Both exist only so the tests can check the two levers of the #37 fix
// against the framework rather than against a restatement of the code. They
// live here, next to the cgo they wrap, for the same reason
// secSuccessStatus does: cgo is not available in _test.go files, so a test
// that needs a C value or a C call needs a Go-side wrapper in this file.
func keychainUIAllowed() (allowed, answered bool) {
	var a C.int
	st := C.sec_user_interaction_allowed(&a)
	return a != 0, int32(st) == secSuccessStatus
}

func queriesRefuseKeychainUI() bool {
	return C.sec_dict_refuses_ui() != 0
}

func (p *PasswordsApp) IsAvailable() error {
	if _, err := os.Stat("/System/Applications/Passwords.app"); err != nil {
		return &ErrUnavailable{Reason: "Passwords.app not found (requires macOS 15+)"}
	}
	return nil
}

// notFoundInBothQueries reports whether both the generic- and
// internet-password queries came back with the definitive "no such item"
// status, as opposed to one of them hitting a real failure (e.g. a locked
// keychain denying access) that a shared/collapsed status would hide.
//
// Note: errSecItemNotFound is also what SecItemCopyMatching returns for an
// item this unsigned process is not entitled to read (see #20, #27) — that
// ambiguity is unresolvable at this layer and this function does not (and
// cannot) distinguish it from a genuine absence.
func notFoundInBothQueries(stGeneric, stInternet int32) bool {
	return stGeneric == secItemNotFoundStatus && stInternet == secItemNotFoundStatus
}

// classifyPasswordsAppLookup maps the pair of OSStatus values behind a NULL
// sec_copy_password/sec_copy_username result onto the Backend error types
// callers switch on, mirroring classifySecurityError (keychain.go),
// classifyBusError (libsecret.go) and classifyCredError (wincred.go). It is
// one function rather than a copy per accessor because divergence between two
// copies of an error classification stays invisible until it costs a
// credential.
func classifyPasswordsAppLookup(service string, stGeneric, stInternet int32) error {
	if notFoundInBothQueries(stGeneric, stInternet) {
		return &ErrNotFound{Service: service}
	}
	return &ErrUnavailable{Reason: fmt.Sprintf(
		"could not read keychain item for %q: Security error (generic query: %d, internet query: %d)",
		service, stGeneric, stInternet)}
}

func (p *PasswordsApp) GetPassword(service string) (string, error) {
	refuseKeychainUI()
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var stGeneric, stInternet C.OSStatus
	pw := C.sec_copy_password(svc, &stGeneric, &stInternet)
	if pw == nil {
		return "", classifyPasswordsAppLookup(service, int32(stGeneric), int32(stInternet))
	}
	defer C.free(unsafe.Pointer(pw))
	return C.GoString(pw), nil
}

func (p *PasswordsApp) GetUsername(service string) (string, error) {
	refuseKeychainUI()
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var stGeneric, stInternet C.OSStatus
	user := C.sec_copy_username(svc, &stGeneric, &stInternet)
	if user == nil {
		return "", classifyPasswordsAppLookup(service, int32(stGeneric), int32(stInternet))
	}
	defer C.free(unsafe.Pointer(user))
	return C.GoString(user), nil
}

func (p *PasswordsApp) Add(service, account, password string) error {
	refuseKeychainUI()
	svc := C.CString(service)
	acct := C.CString(account)
	pw := C.CString(password)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	defer C.free(unsafe.Pointer(pw))
	if st := C.sec_add_generic_password(svc, acct, pw); st != C.errSecSuccess {
		return fmt.Errorf("failed to add secret for '%s': Security error %d", service, st)
	}
	return nil
}

func (p *PasswordsApp) Delete(service string) error {
	refuseKeychainUI()
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	st := C.sec_delete_item(svc)
	if st == C.errSecItemNotFound {
		return &ErrNotFound{Service: service}
	}
	if st != C.errSecSuccess {
		return fmt.Errorf("failed to delete secret for '%s': Security error %d", service, st)
	}
	return nil
}

func (p *PasswordsApp) Edit() error {
	return exec.Command("open", "-b", "com.apple.Passwords").Start()
}

// List returns the deduplicated, sorted service names found across the
// generic-password and internet-password keychain classes.
//
// The two underlying SecItemCopyMatching queries are independent and can
// disagree: one may succeed while the other is denied (e.g.
// errSecInteractionNotAllowed on a locked keychain), or both may genuinely
// find nothing (errSecItemNotFound, which is not an error). If either query
// fails for a reason other than "not found", List returns an error rather
// than silently returning whatever the other query found — a partial
// result would reintroduce the same "denied looks like empty" problem this
// method exists to avoid, just for half the store instead of all of it.
func (p *PasswordsApp) List() ([]string, error) {
	refuseKeychainUI()
	var stGeneric, stInternet C.OSStatus
	raw := C.sec_copy_all_services(&stGeneric, &stInternet)
	defer func() {
		if raw != nil {
			C.free(unsafe.Pointer(raw))
		}
	}()

	if isRealFailure(int32(stGeneric)) || isRealFailure(int32(stInternet)) {
		return nil, fmt.Errorf("failed to list secrets: Security error (generic query: %d, internet query: %d)", stGeneric, stInternet)
	}

	if raw == nil {
		return []string{}, nil
	}
	return DedupeSortServices(strings.Split(C.GoString(raw), "\n")), nil
}

// secSuccessStatus and secItemNotFoundStatus mirror the OSStatus values
// isRealFailure treats as "not a failure", captured as plain int32s rather
// than referenced as C.OSStatus so isRealFailure and notFoundInBothQueries —
// and the tests that drive them — don't need a cgo preamble; cgo is not
// supported in _test.go files.
var (
	secSuccessStatus      = int32(C.errSecSuccess)
	secItemNotFoundStatus = int32(C.errSecItemNotFound)
)

// isRealFailure reports whether st represents an actual failure to query
// the keychain, as opposed to success or a genuine "no items" result.
func isRealFailure(st int32) bool {
	return st != secSuccessStatus && st != secItemNotFoundStatus
}
