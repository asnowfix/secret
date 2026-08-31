//go:build darwin

package backend

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

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
static char* sec_copy_password(const char *name, OSStatus *st) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnData, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef r = NULL;
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
			char *out = _cfdata_to_cstr((CFDataRef)r);
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnData, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef r = NULL;
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
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
static char* sec_copy_username(const char *name, OSStatus *st) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef r = NULL;
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
			CFStringRef acct = CFDictionaryGetValue((CFDictionaryRef)r, kSecAttrAccount);
			char *out = acct ? _cfstring_to_cstr(acct) : NULL;
			CFRelease(r); CFRelease(n);
			return out;
		}
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef r = NULL;
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
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
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 4,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 3,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		st = SecItemDelete(q);
		CFRelease(q);
		if (st == errSecSuccess) { CFRelease(n); return st; }
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer, kSecAttrSynchronizable};
		const void *v[] = {kSecClassInternetPassword, n, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 3,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
	"unsafe"
)

// PasswordsApp implements Backend using the Security framework directly via cgo.
// It searches the default keychain list (including iCloud Keychain) so credentials
// managed by Passwords.app on macOS 15+ are visible alongside login keychain items.
type PasswordsApp struct{}

func NewPasswordsApp() *PasswordsApp { return &PasswordsApp{} }

func (p *PasswordsApp) IsAvailable() error {
	if _, err := os.Stat("/System/Applications/Passwords.app"); err != nil {
		return &ErrUnavailable{Reason: "Passwords.app not found (requires macOS 15+)"}
	}
	return nil
}

func (p *PasswordsApp) GetPassword(service string) (string, error) {
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var st C.OSStatus
	pw := C.sec_copy_password(svc, &st)
	if pw == nil {
		return "", &ErrNotFound{Service: service}
	}
	defer C.free(unsafe.Pointer(pw))
	return C.GoString(pw), nil
}

func (p *PasswordsApp) GetUsername(service string) (string, error) {
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var st C.OSStatus
	user := C.sec_copy_username(svc, &st)
	if user == nil {
		return "", &ErrNotFound{Service: service}
	}
	defer C.free(unsafe.Pointer(user))
	return C.GoString(user), nil
}

func (p *PasswordsApp) Add(service, account, password string) error {
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
// than referenced as C.OSStatus so isRealFailure — and the test that drives
// it — don't need a cgo preamble; cgo is not supported in _test.go files.
var (
	secSuccessStatus      = int32(C.errSecSuccess)
	secItemNotFoundStatus = int32(C.errSecItemNotFound)
)

// isRealFailure reports whether st represents an actual failure to query
// the keychain, as opposed to success or a genuine "no items" result.
func isRealFailure(st int32) bool {
	return st != secSuccessStatus && st != secItemNotFoundStatus
}
