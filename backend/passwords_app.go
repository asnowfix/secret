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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
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
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 4,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = SecItemAdd(attrs, NULL);
	CFRelease(attrs); CFRelease(data); CFRelease(acct); CFRelease(svc);
	return st;
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

// osStatusItemNotFound mirrors C.errSecItemNotFound as a plain int32 so
// notFoundInBothQueries — and the test that drives it — don't need a cgo
// preamble; `import "C"` is not permitted in _test.go files.
var osStatusItemNotFound = int32(C.errSecItemNotFound)

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
	return stGeneric == osStatusItemNotFound && stInternet == osStatusItemNotFound
}

func (p *PasswordsApp) GetPassword(service string) (string, error) {
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var stGeneric, stInternet C.OSStatus
	pw := C.sec_copy_password(svc, &stGeneric, &stInternet)
	if pw == nil {
		if notFoundInBothQueries(int32(stGeneric), int32(stInternet)) {
			return "", &ErrNotFound{Service: service}
		}
		return "", &ErrUnavailable{Reason: fmt.Sprintf("could not read keychain item for %q: Security error (generic query: %d, internet query: %d)", service, stGeneric, stInternet)}
	}
	defer C.free(unsafe.Pointer(pw))
	return C.GoString(pw), nil
}

func (p *PasswordsApp) GetUsername(service string) (string, error) {
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
	var stGeneric, stInternet C.OSStatus
	user := C.sec_copy_username(svc, &stGeneric, &stInternet)
	if user == nil {
		if notFoundInBothQueries(int32(stGeneric), int32(stInternet)) {
			return "", &ErrNotFound{Service: service}
		}
		return "", &ErrUnavailable{Reason: fmt.Sprintf("could not read keychain item for %q: Security error (generic query: %d, internet query: %d)", service, stGeneric, stInternet)}
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
