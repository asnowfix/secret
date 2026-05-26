package backend

import "fmt"

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
