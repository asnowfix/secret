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
static char* sec_copy_all_services(OSStatus *st) {
	CFMutableStringRef out = CFStringCreateMutable(NULL, 0);
	int found = 0;

	{
		const void *k[] = {kSecClass, kSecReturnAttributes, kSecMatchLimit, kSecAttrSynchronizable};
		const void *v[] = {kSecClassGenericPassword, kCFBooleanTrue, kSecMatchLimitAll, kSecAttrSynchronizableAny};
		CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef r = NULL;
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
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
		*st = SecItemCopyMatching(q, &r);
		CFRelease(q);
		if (*st == errSecSuccess && r) {
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

	*st = errSecSuccess;
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
	"sort"
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

func (p *PasswordsApp) List() ([]string, error) {
	var st C.OSStatus
	raw := C.sec_copy_all_services(&st)
	if raw == nil {
		return []string{}, nil
	}
	defer C.free(unsafe.Pointer(raw))
	return dedupeSortedServices(C.GoString(raw)), nil
}

// dedupeSortedServices splits a "\n"-joined list of service names, drops
// empty entries and duplicates, and returns them sorted.
func dedupeSortedServices(joined string) []string {
	names := strings.Split(joined, "\n")
	seen := make(map[string]bool, len(names))
	services := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		services = append(services, n)
	}
	sort.Strings(services)
	return services
}
