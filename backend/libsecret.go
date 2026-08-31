//go:build linux

// Package backend — Linux Secret Service backend.
//
// This talks directly to the freedesktop.org Secret Service D-Bus API
// (https://specifications.freedesktop.org/secret-service/latest/) via
// github.com/godbus/dbus/v5, rather than shelling out to `secret-tool` or
// adopting a full third-party keyring library. See the PR description for
// the full rationale; in short:
//
//   - secret-tool (libsecret's CLI) has no way to enumerate items — its
//     subcommands are store/lookup/clear/search/lock, and search requires
//     already knowing the attribute values to look for. Once List() became
//     a required Backend method (see backend/backend.go), that ruled
//     secret-tool out: there is no "list everything" it can be asked to do.
//     The D-Bus API, by contrast, exposes each collection's Items property
//     and each item's Attributes property as plain metadata, readable
//     without unlocking the item's secret — real enumeration, not a
//     workaround.
//   - A third-party keyring library (zalando/go-keyring, 99designs/keyring)
//     would, on Linux, reimplement essentially this same D-Bus client code
//     internally; pulling one in only to use its Linux code path adds a
//     dependency (and, for 99designs/keyring, a much larger transitive one
//     bundling unrelated backends: pass, encrypted files, KWallet-via-dbus,
//     etc.) without saving meaningful effort over depending on the same
//     underlying D-Bus binding (godbus/dbus/v5) directly.
//
// The trade-off accepted here is owning the session/attribute/prompt
// plumbing against the spec, verified against a real gnome-keyring-daemon
// in a headless dbus-run-session (both locally, in a throwaway container,
// and in CI — see .github/workflows/ci.yml and libsecret_live_test.go).
package backend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const secretsDest = "org.freedesktop.secrets"

var (
	secretsPath  = dbus.ObjectPath("/org/freedesktop/secrets")
	defaultAlias = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	rootPath     = dbus.ObjectPath("/")
)

const (
	ifaceService    = "org.freedesktop.Secret.Service"
	ifaceCollection = "org.freedesktop.Secret.Collection"
	ifaceItem       = "org.freedesktop.Secret.Item"
	ifacePrompt     = "org.freedesktop.Secret.Prompt"

	itemLabelProp = "org.freedesktop.Secret.Item.Label"
	itemAttrsProp = "org.freedesktop.Secret.Item.Attributes"
)

// Attribute keys used to tag every item this backend creates. "username" is
// left empty (but still present) for services stored without an account.
const (
	attrService  = "service"
	attrUsername = "username"
)

// promptWaitTimeout bounds how long we wait for a user to respond to a
// Secret Service unlock/create prompt (e.g. a GUI "unlock your keyring"
// dialog) before giving up.
const promptWaitTimeout = 2 * time.Minute

// secretValue mirrors the Secret Service API's "Secret" D-Bus struct:
// (session: ObjectPath, parameters: Array<Byte>, value: Array<Byte>,
// content_type: String). We always use the "plain" session algorithm, so
// Parameters is always empty — the session is already confined to a local,
// per-user D-Bus socket, so there is nothing meaningful to encrypt against.
type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// objectFunc returns the D-Bus proxy object for dest/path. It exists so
// tests can substitute a fake without a real D-Bus connection; connect()
// wires it to the real (*dbus.Conn).Object.
type objectFunc func(dest string, path dbus.ObjectPath) dbus.BusObject

// promptFunc drives a Secret Service Prompt object to completion and
// returns its result variant. Tests substitute a fake; connect() wires it
// to runPromptOnConn.
type promptFunc func(path dbus.ObjectPath) (dbus.Variant, error)

// SecretService implements Backend via the freedesktop.org Secret Service
// D-Bus API, covering GNOME Keyring and any other provider implementing the
// same spec (e.g. KWallet's ksecretd).
type SecretService struct {
	conn    *dbus.Conn
	session dbus.ObjectPath
	object  objectFunc
	prompt  promptFunc
}

// NewSecretService returns a Backend that talks to the Secret Service over
// D-Bus. The connection is established lazily, on first use.
func NewSecretService() *SecretService {
	return &SecretService{}
}

// connect lazily opens the session D-Bus connection and a Secret Service
// session. It is idempotent: once established, later calls are no-ops.
func (s *SecretService) connect() error {
	if s.conn != nil {
		return nil
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return &ErrUnavailable{Reason: fmt.Sprintf(
			"no D-Bus session bus available (%v) — secret needs a desktop session (or a manually started one, e.g. via dbus-run-session) with DBUS_SESSION_BUS_ADDRESS set",
			err,
		)}
	}
	object := func(dest string, path dbus.ObjectPath) dbus.BusObject { return conn.Object(dest, path) }

	call := object(secretsDest, secretsPath).Call(ifaceService+".OpenSession", 0, "plain", dbus.MakeVariant(""))
	if call.Err != nil {
		conn.Close()
		return classifyBusError(call.Err)
	}
	var algoOutput dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := call.Store(&algoOutput, &sessionPath); err != nil {
		conn.Close()
		return &ErrUnavailable{Reason: fmt.Sprintf("unexpected reply from Secret Service OpenSession: %v", err)}
	}

	s.conn = conn
	s.object = object
	s.session = sessionPath
	s.prompt = func(path dbus.ObjectPath) (dbus.Variant, error) { return runPromptOnConn(conn, path) }
	return nil
}

func (s *SecretService) service() dbus.BusObject { return s.object(secretsDest, secretsPath) }
func (s *SecretService) coll() dbus.BusObject    { return s.object(secretsDest, defaultAlias) }

// IsAvailable checks that a session D-Bus bus and a Secret Service provider
// are both reachable.
func (s *SecretService) IsAvailable() error {
	return s.connect()
}

// GetUsername retrieves the account/username for the given service.
func (s *SecretService) GetUsername(service string) (string, error) {
	if err := s.connect(); err != nil {
		return "", err
	}
	item, err := s.resolveItem(service)
	if err != nil {
		return "", err
	}
	attrs, err := s.itemAttributes(item)
	if err != nil {
		return "", &ErrNotFound{Service: service}
	}
	return attrs[attrUsername], nil
}

// GetPassword retrieves the password for the given service.
func (s *SecretService) GetPassword(service string) (string, error) {
	if err := s.connect(); err != nil {
		return "", err
	}
	item, err := s.resolveItem(service)
	if err != nil {
		return "", err
	}
	call := s.object(secretsDest, item).Call(ifaceItem+".GetSecret", 0, s.session)
	if call.Err != nil {
		return "", &ErrNotFound{Service: service}
	}
	var sec secretValue
	if err := call.Store(&sec); err != nil {
		return "", &ErrNotFound{Service: service}
	}
	return string(sec.Value), nil
}

// Add stores a credential. CreateItem's `replace` flag overwrites any
// existing item whose attributes match exactly (same service *and* same
// account); a different account under the same service is a distinct item.
// cmd/set.go's overwrite-confirmation flow already calls Delete(service)
// first when it wants an unconditional replace, which removes every item
// for that service regardless of account (see Delete below).
func (s *SecretService) Add(service, account, password string) error {
	if err := s.connect(); err != nil {
		return err
	}
	props := map[string]dbus.Variant{
		itemLabelProp: dbus.MakeVariant(buildItemLabel(service, account)),
		itemAttrsProp: dbus.MakeVariant(map[string]string{
			attrService:  service,
			attrUsername: account,
		}),
	}
	sec := secretValue{
		Session:     s.session,
		Parameters:  []byte{},
		Value:       []byte(password),
		ContentType: "text/plain; charset=utf8",
	}
	call := s.coll().Call(ifaceCollection+".CreateItem", 0, props, sec, true)
	if call.Err != nil {
		return fmt.Errorf("failed to add secret for '%s': %w", service, classifyBusError(call.Err))
	}
	var itemPath, promptPath dbus.ObjectPath
	if err := call.Store(&itemPath, &promptPath); err != nil {
		return fmt.Errorf("failed to add secret for '%s': unexpected reply from Secret Service CreateItem: %w", service, err)
	}
	if promptPath != rootPath {
		if _, err := s.prompt(promptPath); err != nil {
			return fmt.Errorf("failed to add secret for '%s': %w", service, err)
		}
	}
	return nil
}

// Delete removes every item tagged with attrService == service, across all
// collections, unlocking locked ones first if needed.
func (s *SecretService) Delete(service string) error {
	if err := s.connect(); err != nil {
		return err
	}
	unlocked, locked, err := s.searchItems(service)
	if err != nil {
		return err
	}
	items := append(append([]dbus.ObjectPath{}, unlocked...), locked...)
	if len(items) == 0 {
		return &ErrNotFound{Service: service}
	}
	for _, item := range items {
		call := s.object(secretsDest, item).Call(ifaceItem+".Delete", 0)
		if call.Err != nil {
			return fmt.Errorf("failed to delete secret for '%s': %w", service, classifyBusError(call.Err))
		}
		var promptPath dbus.ObjectPath
		if err := call.Store(&promptPath); err == nil && promptPath != rootPath {
			if _, err := s.prompt(promptPath); err != nil {
				return fmt.Errorf("failed to delete secret for '%s': %w", service, err)
			}
		}
	}
	return nil
}

// List enumerates the service names of every item across every collection
// the Secret Service provider manages, by walking Service.Collections and
// each Collection's Items property, then reading each item's Attributes.
// Attribute metadata is public (unlike the secret value itself), so this
// works without unlocking anything.
func (s *SecretService) List() ([]string, error) {
	if err := s.connect(); err != nil {
		return nil, err
	}
	collsVariant, err := s.service().GetProperty(ifaceService + ".Collections")
	if err != nil {
		return nil, fmt.Errorf("failed to list Secret Service collections: %w", err)
	}
	colls, ok := collsVariant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, fmt.Errorf("unexpected Collections value type %T", collsVariant.Value())
	}

	var names []string
	for _, c := range colls {
		itemsVariant, err := s.object(secretsDest, c).GetProperty(ifaceCollection + ".Items")
		if err != nil {
			// Best-effort: a collection we can't currently enumerate (e.g. a
			// transient race right after activation) shouldn't fail the
			// whole listing.
			continue
		}
		items, ok := itemsVariant.Value().([]dbus.ObjectPath)
		if !ok {
			continue
		}
		for _, it := range items {
			attrs, err := s.itemAttributes(it)
			if err != nil {
				continue
			}
			if svc := attrs[attrService]; svc != "" {
				names = append(names, svc)
			}
		}
	}
	return dedupSorted(names), nil
}

// Edit has no sensible equivalent on Linux: there is no single native
// credential-manager UI guaranteed to be installed across GNOME/KDE/other
// desktops the way Keychain Access or the Windows Credential Manager applet
// are on their platforms. Rather than guess at (and shell out to) a
// front-end that may not exist — Seahorse, KWalletManager, or similar are
// all optional packages — this returns a clear, actionable error.
func (s *SecretService) Edit() error {
	return fmt.Errorf("no native secret-manager UI is available on Linux; inspect or edit items directly with a tool like 'secret-tool' or your desktop's keyring app (e.g. Seahorse, KWalletManager)")
}

// resolveItem finds a single item tagged with attrService == service,
// unlocking it first if it exists but is locked.
func (s *SecretService) resolveItem(service string) (dbus.ObjectPath, error) {
	unlocked, locked, err := s.searchItems(service)
	if err != nil {
		return "", err
	}
	if item, ok := pickItem(unlocked); ok {
		return item, nil
	}
	if len(locked) == 0 {
		return "", &ErrNotFound{Service: service}
	}
	newlyUnlocked, err := s.unlock(locked)
	if err != nil {
		return "", err
	}
	if item, ok := pickItem(newlyUnlocked); ok {
		return item, nil
	}
	return "", &ErrNotFound{Service: service}
}

// pickItem returns the first candidate item, if any. Multiple items can
// exist for the same service if they were created under different accounts
// (see Add's doc comment); we deterministically pick the first one Secret
// Service returns, mirroring the ambiguity accepted by the macOS and
// Windows backends' single-match-by-service-name lookups.
func pickItem(candidates []dbus.ObjectPath) (dbus.ObjectPath, bool) {
	if len(candidates) == 0 {
		return "", false
	}
	return candidates[0], true
}

// searchItems finds items across all collections tagged with
// attrService == service, split into already-unlocked and locked.
func (s *SecretService) searchItems(service string) (unlocked, locked []dbus.ObjectPath, err error) {
	call := s.service().Call(ifaceService+".SearchItems", 0, map[string]string{attrService: service})
	if call.Err != nil {
		return nil, nil, classifyBusError(call.Err)
	}
	if err := call.Store(&unlocked, &locked); err != nil {
		return nil, nil, fmt.Errorf("unexpected reply from Secret Service SearchItems: %w", err)
	}
	return unlocked, locked, nil
}

// unlock unlocks the given items, driving any resulting prompt (e.g. a
// desktop "unlock your keyring" dialog) to completion.
func (s *SecretService) unlock(paths []dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	call := s.service().Call(ifaceService+".Unlock", 0, paths)
	if call.Err != nil {
		return nil, classifyBusError(call.Err)
	}
	var unlocked []dbus.ObjectPath
	var promptPath dbus.ObjectPath
	if err := call.Store(&unlocked, &promptPath); err != nil {
		return nil, fmt.Errorf("unexpected reply from Secret Service Unlock: %w", err)
	}
	if promptPath != rootPath {
		result, err := s.prompt(promptPath)
		if err != nil {
			return nil, err
		}
		if arr, ok := result.Value().([]dbus.ObjectPath); ok {
			unlocked = arr
		}
	}
	return unlocked, nil
}

// itemAttributes reads an item's Attributes property. This is public
// metadata, readable without unlocking the item's secret value.
func (s *SecretService) itemAttributes(item dbus.ObjectPath) (map[string]string, error) {
	v, err := s.object(secretsDest, item).GetProperty(itemAttrsProp)
	if err != nil {
		return nil, err
	}
	attrs, ok := v.Value().(map[string]string)
	if !ok {
		return nil, fmt.Errorf("unexpected Attributes value type %T", v.Value())
	}
	return attrs, nil
}

// buildItemLabel formats the human-readable label shown by keyring UIs
// (e.g. Seahorse) for an item created by this backend.
func buildItemLabel(service, account string) string {
	if account == "" {
		return service
	}
	return fmt.Sprintf("%s (%s)", service, account)
}

// classifyBusError translates a D-Bus error into a typed backend error.
// "ServiceUnknown" (no .service file registers org.freedesktop.secrets) and
// spawn failures both mean "no Secret Service provider is running" — the
// single most likely real-world failure, so it gets an actionable message.
// Anything else is surfaced as-is, wrapped as ErrUnavailable, since it
// indicates something about the D-Bus session itself is unhealthy rather
// than a missing credential (missing credentials are ErrNotFound, produced
// by the callers above, not here).
func classifyBusError(err error) error {
	var derr dbus.Error
	if errors.As(err, &derr) {
		if derr.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || strings.Contains(derr.Name, "Spawn") {
			return &ErrUnavailable{Reason: fmt.Sprintf(
				"no Secret Service provider registered on the session D-Bus (%s) — start gnome-keyring-daemon --components=secrets, KWallet's ksecretd, or another Secret Service implementation",
				derr.Name,
			)}
		}
		return &ErrUnavailable{Reason: fmt.Sprintf("Secret Service D-Bus call failed: %s: %v", derr.Name, derr.Body)}
	}
	return &ErrUnavailable{Reason: err.Error()}
}

// dedupSorted returns a sorted copy of names with exact, case-sensitive
// duplicates removed.
//
// TODO(#24): replace with the shared dedup+sort helper being added to
// backend/backend.go by PR #24 (list-secrets-command) once this branch
// rebases onto it, so all backends share one implementation.
func dedupSorted(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	out := make([]string, 0, len(sorted))
	for i, n := range sorted {
		if i == 0 || n != sorted[i-1] {
			out = append(out, n)
		}
	}
	return out
}

// runPromptOnConn drives a Secret Service Prompt object to completion:
// it subscribes to the object's Completed signal, calls Prompt(), and
// waits for the signal (or a timeout, in case a GUI dialog is never
// answered). This is package-level (rather than a SecretService method) so
// it can close over a plain *dbus.Conn without needing the objectFunc
// indirection used elsewhere for testability — nothing about prompt-driving
// is exercised by the unit tests, only by the live integration test.
func runPromptOnConn(conn *dbus.Conn, path dbus.ObjectPath) (dbus.Variant, error) {
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(path),
		dbus.WithMatchInterface(ifacePrompt),
	); err != nil {
		return dbus.Variant{}, err
	}
	ch := make(chan *dbus.Signal, 1)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	if call := conn.Object(secretsDest, path).Call(ifacePrompt+".Prompt", 0, ""); call.Err != nil {
		return dbus.Variant{}, call.Err
	}

	ctx, cancel := context.WithTimeout(context.Background(), promptWaitTimeout)
	defer cancel()
	select {
	case sig, ok := <-ch:
		if !ok {
			return dbus.Variant{}, fmt.Errorf("Secret Service signal channel closed while waiting for prompt")
		}
		if sig.Name != ifacePrompt+".Completed" || len(sig.Body) != 2 {
			return dbus.Variant{}, fmt.Errorf("unexpected signal %q while waiting for Secret Service prompt", sig.Name)
		}
		dismissed, _ := sig.Body[0].(bool)
		if dismissed {
			return dbus.Variant{}, fmt.Errorf("Secret Service prompt was dismissed")
		}
		result, _ := sig.Body[1].(dbus.Variant)
		return result, nil
	case <-ctx.Done():
		return dbus.Variant{}, fmt.Errorf("timed out waiting for Secret Service prompt to complete")
	}
}
