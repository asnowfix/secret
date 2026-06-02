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
static char* sec_copy_password(const char *name, OSStatus *st) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnData, kSecMatchLimit};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
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
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnData, kSecMatchLimit};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
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
static char* sec_copy_username(const char *name, OSStatus *st) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);

	{
		const void *k[] = {kSecClass, kSecAttrService, kSecReturnAttributes, kSecMatchLimit};
		const void *v[] = {kSecClassGenericPassword, n, kCFBooleanTrue, kSecMatchLimitOne};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
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
		const void *k[] = {kSecClass, kSecAttrServer, kSecReturnAttributes, kSecMatchLimit};
		const void *v[] = {kSecClassInternetPassword, n, kCFBooleanTrue, kSecMatchLimitOne};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
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

// sec_delete_item deletes an item by service name.
// Tries kSecClassGenericPassword then kSecClassInternetPassword.
static OSStatus sec_delete_item(const char *name) {
	CFStringRef n = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	OSStatus st;

	{
		const void *k[] = {kSecClass, kSecAttrService};
		const void *v[] = {kSecClassGenericPassword, n};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 2,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		st = SecItemDelete(q);
		CFRelease(q);
		if (st == errSecSuccess) { CFRelease(n); return st; }
	}

	{
		const void *k[] = {kSecClass, kSecAttrServer};
		const void *v[] = {kSecClassInternetPassword, n};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 2,
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
