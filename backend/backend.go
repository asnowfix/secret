package backend

import (
	"fmt"
	"sort"
)

// Backend defines the interface that all secret-store backends must implement.
type Backend interface {
	// IsAvailable returns true if this backend can be used on the current system.
	IsAvailable() error

	// GetUsername retrieves the account/username for the given service.
	GetUsername(service string) (string, error)

	// GetPassword retrieves the password for the given service.
	GetPassword(service string) (string, error)

	// Add stores a credential (service, account, password) in the backend.
	Add(service, account, password string) error

	// Delete removes the credential for the given service.
	Delete(service string) error

	// Edit opens the backend's native UI for credential management.
	Edit() error

	// List returns the service names of all secrets available in this backend:
	// deduplicated by an exact, case-sensitive match, and sorted with
	// sort.Strings (ordinal byte-wise ordering — not locale- or
	// Unicode-aware collation). A backend that has no way to enumerate its
	// secrets at all — for example one that only speaks a protocol with no
	// "list everything" verb — may return *ErrNotSupported instead of a
	// result.
	List() ([]string, error)
}

// ErrNotFound is returned when a credential cannot be found.
type ErrNotFound struct {
	Service string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("did not find credentials for '%s'", e.Service)
}

// ErrUnavailable is returned when a backend cannot be used.
type ErrUnavailable struct {
	Reason string
}

func (e *ErrUnavailable) Error() string {
	return e.Reason
}

// ErrNotSupported is returned when a backend does not implement a given
// operation at all — as opposed to the operation failing at runtime. Op
// names the unsupported operation, e.g. "List". It is purely additive to
// the Backend interface: existing backends are not required to return it,
// and it exists for backends (such as ones speaking a browser-integration
// protocol with no "list everything" verb) that can support Get/Add/Delete
// but have no way to enumerate their secrets.
type ErrNotSupported struct {
	Op string
}

func (e *ErrNotSupported) Error() string {
	return fmt.Sprintf("%s is not supported by this backend", e.Op)
}

// DedupeSortServices removes duplicate service names (an exact,
// case-sensitive match) and empty entries, and returns the remainder
// sorted with sort.Strings (ordinal byte-wise ordering). All Backend
// implementations of List should route their raw results through this so
// dedup and ordering stay identical across backends.
func DedupeSortServices(names []string) []string {
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
