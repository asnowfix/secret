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
// waiting, on every entry point: the read paths classify it through
// classifyPasswordsAppLookup, Delete through classifyPasswordsAppDelete, and
// Add and List construct *ErrUnavailable directly. So the caller gets a typed,
// actionable error rather than a hang — and never *ErrNotFound, which would
// turn "I could not tell" into "it is not there".
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
// It builds into a mutable dictionary rather than copying into a fixed-size
// stack buffer: with no buffer there is no size to get wrong, no bounds
// check to get wrong (a signed CFIndex makes "n too large" and "n negative"
// two separate mistakes), and no failure return for the callers to check —
// so no way for this to hand back a NULL that the nine CFRelease(q) sites
// would turn into a crash.
static CFDictionaryRef _no_ui_dict(const void **k, const void **v, CFIndex n) {
	CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, n + 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	for (CFIndex i = 0; i < n; i++) CFDictionarySetValue(d, k[i], v[i]);
	CFDictionarySetValue(d, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	return d;
}

// sec_dict_refuses_ui reports whether a dictionary built by _no_ui_dict
// carries the refuse-UI key. It exists for the test: cgo constants are not
// reachable from _test.go files, so this is how Go-side tests check the one
// construction path every query goes through.
static int sec_dict_refuses_ui(void) {
	const void *k[] = {kSecClass};
	const void *v[] = {kSecClassGenericPassword};
	CFDictionaryRef q = _no_ui_dict(k, v, 1);
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
//
// The two deletes' OSStatus results are reported separately via stGeneric/
// stInternet, for the same reason sec_copy_password and sec_copy_all_services
// do it, and with more at stake. This function used to keep one shared status
// that the internet-class delete overwrote unconditionally, so a generic-class
// delete that failed for a real reason was reported as whatever the internet
// query said — and the internet query, matching no kSecAttrServer item,
// says errSecItemNotFound.
//
// That collapse became reachable the moment this file started refusing
// keychain UI. An item whose ACL does not grant this binary (issue #44) used
// to block the generic delete on an authorization dialog; it now returns
// errSecInteractionNotAllowed immediately, which is precisely the status the
// shared variable then threw away. The caller saw "nothing to delete", and
// cmd/gitcredential.go suppresses *ErrNotFound from Delete entirely, so
// `git credential reject` reported success having deleted nothing. That is
// issue #36 / #30's bug class, on the shipped macOS default backend; commit
// 1cd8575 fixed the identical collapse in Keychain.Delete and in this file's
// read path, and this delete path was the one it missed.
static void sec_delete_item(const char *name, OSStatus *stGeneric, OSStatus *stInternet) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	*stGeneric = errSecItemNotFound;
	*stInternet = errSecItemNotFound;

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 3);
		*stGeneric = SecItemDelete(q);
		CFRelease(q);
		// A generic-class hit is the whole job: return without attempting
		// the internet class, leaving stInternet at its "not attempted, and
		// therefore not found" initial value.
		if (*stGeneric == errSecSuccess) { CFRelease(n); return; }
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kSecAttrSynchronizableAny};
		CFDictionaryRef q = _no_ui_dict(k, v, 3);
		*stInternet = SecItemDelete(q);
		CFRelease(q);
	}

	CFRelease(n);
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
// refuseKeychainUIStatus records what that one attempt returned, because
// sync.Once *latches*: if the lever fails, it is never retried for the life
// of the process. Without recording it, a hang caused by the lever having
// silently failed would be indistinguishable from the residual risk this
// design does knowingly accept (a wedged securityd) — and the whole point of
// the #37 fix is that a caller can tell what happened to it.
//
// attempted is tracked separately rather than inferred from status, because
// the zero value of an OSStatus *is* errSecSuccess: "the lever succeeded" and
// "the lever was never run, and nothing recorded anything" would otherwise be
// the same value, which is exactly the confusion this variable exists to
// remove.
var (
	refuseKeychainUIOnce   sync.Once
	refuseKeychainUIResult struct {
		attempted bool
		status    int32
	}
)

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
//   - Its failure does not stop the operation, but is not swallowed either.
//     If the call fails, the worst case is exactly the pre-#37 behaviour on
//     the legacy path and kSecUseAuthenticationUIFail still covers the Data
//     Protection path, so refusing to run at all would be a strictly worse
//     trade. It is recorded in refuseKeychainUIResult and appended to
//     whatever error the operation goes on to produce, so a lever that
//     silently failed is visible in the diagnostic rather than only in the
//     symptom.
func refuseKeychainUI() {
	refuseKeychainUIOnce.Do(func() {
		refuseKeychainUIResult.status = int32(C.sec_refuse_user_interaction())
		refuseKeychainUIResult.attempted = true
	})
}

// refuseKeychainUINote reports that the UI-refusal lever itself failed, for
// appending to an error message. Empty in the normal case, which is every
// case observed so far, and empty before the lever has been run at all —
// every path that can produce an error runs it first.
func refuseKeychainUINote() string {
	if !refuseKeychainUIResult.attempted || refuseKeychainUIResult.status == secSuccessStatus {
		return ""
	}
	return fmt.Sprintf(
		" (note: SecKeychainSetUserInteractionAllowed failed with Security error %d,"+
			" so legacy-keychain calls in this process may still be waiting on a dialog)",
		refuseKeychainUIResult.status)
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

// interactionRefusedNote explains errSecInteractionNotAllowed, and says what
// to do about it, when it appears among statuses. Empty for every other
// status.
//
// It gets a name and a remedy because this package is what produces it:
// refuseKeychainUI and kSecUseAuthenticationUIFail deliberately convert every
// keychain dialog into this status (#37), which makes it the expected failure
// for the two cases a user is most likely to hit and least able to diagnose
// from a bare number — a locked login keychain, and an item whose access
// control does not cover this binary (#44). Before that change those cases
// showed a dialog; a user who answered it got their credential, and one who
// could not at least saw something. They now get an error, so the error has
// to carry what the dialog would have.
//
// Cause first, remedy second, and the remedy phrased as a suggestion —
// keychainUnavailableReason (keychain.go) records why: a message that asserts
// one cause stays wrong for every other one. Every status other than
// errSecInteractionNotAllowed keeps the bare numeric form for exactly that
// reason.
func interactionRefusedNote(statuses ...int32) string {
	for _, st := range statuses {
		if st == secInteractionNotAllowedStatus {
			return " — macOS needed a keychain dialog to answer this and secret refuses" +
				" them, so the item could not be reached; if your login keychain is locked," +
				" unlocking it and retrying should fix this, and if it is already unlocked" +
				" the item's access control most likely does not cover this binary"
		}
	}
	return ""
}

// classifyPasswordsAppStatuses maps a pair of OSStatus values from the
// generic- and internet-class calls onto the Backend error types callers
// switch on, mirroring classifySecurityError (keychain.go), classifyBusError
// (libsecret.go) and classifyCredError (wincred.go).
//
// Only a definitive miss in *both* classes may be *ErrNotFound. cmd/set.go
// reads that as "safe to overwrite" and cmd/gitcredential.go suppresses it
// from Delete entirely, so anything less certain has to be *ErrUnavailable:
// "I could not tell" reported as "it is not there" is issue #30's bug class,
// and #36's, and it is the one this project has spent four issues removing.
//
// op names the operation for the message ("read", "delete"), the way
// classifySecurityError does in keychain.go.
func classifyPasswordsAppStatuses(op, service string, stGeneric, stInternet int32) error {
	if notFoundInBothQueries(stGeneric, stInternet) {
		return &ErrNotFound{Service: service}
	}
	return &ErrUnavailable{Reason: fmt.Sprintf(
		"could not %s keychain item for %q: Security error (generic query: %d, internet query: %d)%s",
		op, service, stGeneric, stInternet,
		interactionRefusedNote(stGeneric, stInternet)+refuseKeychainUINote())}
}

// classifyPasswordsAppLookup classifies a NULL sec_copy_password /
// sec_copy_username result. It is one function rather than a copy per
// accessor because divergence between two copies of an error classification
// stays invisible until it costs a credential.
func classifyPasswordsAppLookup(service string, stGeneric, stInternet int32) error {
	return classifyPasswordsAppStatuses("read", service, stGeneric, stInternet)
}

// classifyPasswordsAppDelete classifies a sec_delete_item result that did not
// succeed in either class. It shares classifyPasswordsAppStatuses with the
// read path deliberately: the delete path had its own, weaker rule — one
// shared status, errSecItemNotFound wins — and that is what made a refused
// authorization report as a successful no-op erase.
func classifyPasswordsAppDelete(service string, stGeneric, stInternet int32) error {
	return classifyPasswordsAppStatuses("delete", service, stGeneric, stInternet)
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
	// A write has no meaningful "not found" outcome, so every failure here is
	// *ErrUnavailable — the same rule, and the same reason, as Keychain.Add.
	if st := C.sec_add_generic_password(svc, acct, pw); st != C.errSecSuccess {
		return &ErrUnavailable{Reason: fmt.Sprintf(
			"failed to add secret for '%s': Security error %d%s",
			service, int32(st), interactionRefusedNote(int32(st))+refuseKeychainUINote())}
	}
	return nil
}

// Delete removes the credential for service, trying the generic-password
// class and then the internet-password class.
//
// Success in either class is a delete. Anything else is classified from
// *both* statuses rather than from whichever one happened to be written
// last: see sec_delete_item's comment for what collapsing them cost.
func (p *PasswordsApp) Delete(service string) error {
	refuseKeychainUI()
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var stGeneric, stInternet C.OSStatus
	C.sec_delete_item(svc, &stGeneric, &stInternet)
	if int32(stGeneric) == secSuccessStatus || int32(stInternet) == secSuccessStatus {
		return nil
	}
	return classifyPasswordsAppDelete(service, int32(stGeneric), int32(stInternet))
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

	// *ErrUnavailable rather than an untyped error, matching Keychain.List:
	// "I could not enumerate the store" is a backend-unavailable condition,
	// and a caller that wants to tell it apart from an empty store needs a
	// type to test, not a string.
	if isRealFailure(int32(stGeneric)) || isRealFailure(int32(stInternet)) {
		return nil, &ErrUnavailable{Reason: fmt.Sprintf(
			"failed to list secrets: Security error (generic query: %d, internet query: %d)%s",
			int32(stGeneric), int32(stInternet),
			interactionRefusedNote(int32(stGeneric), int32(stInternet))+refuseKeychainUINote())}
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
//
// secInteractionNotAllowedStatus is here for the same reason but a different
// purpose: it is the status this file's UI refusal deliberately produces
// (#37), so it is the one failure interactionRefusedNote can explain rather
// than merely number.
var (
	secSuccessStatus               = int32(C.errSecSuccess)
	secItemNotFoundStatus          = int32(C.errSecItemNotFound)
	secInteractionNotAllowedStatus = int32(C.errSecInteractionNotAllowed)
)

// isRealFailure reports whether st represents an actual failure to query
// the keychain, as opposed to success or a genuine "no items" result.
func isRealFailure(st int32) bool {
	return st != secSuccessStatus && st != secItemNotFoundStatus
}
