//go:build windows

// Package backend — Windows Credential Manager implementation.
//
// Uses the Win32 Credential Manager API (Advapi32.dll) directly via syscalls
// — no cgo, no third-party wincred library.
//
// Credentials are stored as CRED_TYPE_GENERIC entries with CRED_PERSIST_LOCAL_MACHINE
// persistence. Passwords are encoded as UTF-16LE blobs, matching how Windows
// natively encodes string credential data.
//
// Edit() opens the built-in Credential Manager UI:
//
//	control.exe /name Microsoft.CredentialManager

package backend

import (
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32          = windows.NewLazySystemDLL("Advapi32.dll")
	procCredRead      = advapi32.NewProc("CredReadW")
	procCredWrite     = advapi32.NewProc("CredWriteW")
	procCredDelete    = advapi32.NewProc("CredDeleteW")
	procCredFree      = advapi32.NewProc("CredFree")
	procCredEnumerate = advapi32.NewProc("CredEnumerateW")
)

const (
	credTypeGeneric         uint32 = 1
	credPersistLocalMachine uint32 = 2

	// credEnumerateAllCredentials must be set when Filter is NULL to enumerate
	// every credential in the caller's credential set, not just the current
	// logon session's.
	credEnumerateAllCredentials uint32 = 0x1
)

// nativeCredential mirrors the CREDENTIALW struct from wincred.h.
type nativeCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        [2]uint32 // FILETIME: LowDateTime, HighDateTime
	CredentialBlobSize uint32
	CredentialBlob     unsafe.Pointer
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// CredentialManager implements Backend using the Windows Credential Manager API.
type CredentialManager struct{}

func NewCredentialManager() *CredentialManager {
	return &CredentialManager{}
}

func (c *CredentialManager) IsAvailable() error {
	if err := advapi32.Load(); err != nil {
		return &ErrUnavailable{Reason: "Windows Credential Manager unavailable: " + err.Error()}
	}
	return nil
}

func (c *CredentialManager) GetUsername(service string) (string, error) {
	cred, err := credReadW(service)
	if err != nil {
		return "", err
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))
	if cred.UserName == nil {
		return "", &ErrNotFound{Service: service}
	}
	return windows.UTF16PtrToString(cred.UserName), nil
}

func (c *CredentialManager) GetPassword(service string) (string, error) {
	cred, err := credReadW(service)
	if err != nil {
		return "", err
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(cred)))
	if cred.CredentialBlobSize == 0 {
		return "", nil
	}
	blob := unsafe.Slice((*uint16)(cred.CredentialBlob), cred.CredentialBlobSize/2)
	return windows.UTF16ToString(blob), nil
}

func (c *CredentialManager) Add(service, account, password string) error {
	targetPtr, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return err
	}
	userPtr, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	blob, err := syscall.UTF16FromString(password)
	if err != nil {
		return err
	}
	blob = blob[:len(blob)-1] // strip null terminator; CredentialBlobSize is byte count of data only

	cred := nativeCredential{
		Type:               credTypeGeneric,
		TargetName:         targetPtr,
		UserName:           userPtr,
		CredentialBlobSize: uint32(len(blob) * 2),
		Persist:            credPersistLocalMachine,
	}
	if len(blob) > 0 {
		cred.CredentialBlob = unsafe.Pointer(&blob[0])
	}

	r, _, e := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0)
	runtime.KeepAlive(blob) // prevent GC of blob backing array before syscall completes
	if r == 0 {
		return fmt.Errorf("failed to add credential for '%s': %w", service, e)
	}
	return nil
}

func (c *CredentialManager) Delete(service string) error {
	targetPtr, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return err
	}
	r, _, _ := procCredDelete.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
	)
	if r == 0 {
		return &ErrNotFound{Service: service}
	}
	return nil
}

func (c *CredentialManager) Edit() error {
	return exec.Command("control.exe", "/name", "Microsoft.CredentialManager").Start()
}

func (c *CredentialManager) List() ([]string, error) {
	var count uint32
	var pCreds **nativeCredential
	r, _, e := procCredEnumerate.Call(
		0, // Filter: NULL enumerates all credentials (with the flag below)
		uintptr(credEnumerateAllCredentials),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pCreds)),
	)
	if r == 0 {
		if e == windows.ERROR_NOT_FOUND {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to enumerate credentials: %w", e)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pCreds)))

	credPtrs := unsafe.Slice(pCreds, count)
	return filterGenericTargetNames(credPtrs), nil
}

// filterGenericTargetNames extracts the target (service) names of
// CRED_TYPE_GENERIC credentials, sorted.
func filterGenericTargetNames(creds []*nativeCredential) []string {
	services := make([]string, 0, len(creds))
	for _, cred := range creds {
		if cred.Type != credTypeGeneric || cred.TargetName == nil {
			continue
		}
		services = append(services, windows.UTF16PtrToString(cred.TargetName))
	}
	sort.Strings(services)
	return services
}

func credReadW(service string) (*nativeCredential, error) {
	targetPtr, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return nil, err
	}
	var pcred *nativeCredential
	r, _, _ := procCredRead.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if r == 0 {
		return nil, &ErrNotFound{Service: service}
	}
	return pcred, nil
}
