//go:build linux

package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// These tests exercise the backend's logic — item resolution, attribute
// plumbing, error classification, and enumeration — against a fake
// dbus.BusObject, so they run unconditionally wherever `go test ./...` runs
// on linux, without a real D-Bus session or Secret Service provider. See
// libsecret_live_test.go for the live-daemon counterpart, gated behind an
// env var.

// fakeObject implements dbus.BusObject for a single object path, backed by
// caller-supplied Call/GetProperty behavior.
type fakeObject struct {
	path dbus.ObjectPath
	call func(method string, args []interface{}) *dbus.Call
	prop func(name string) (dbus.Variant, error)
}

func (f *fakeObject) Call(method string, _ dbus.Flags, args ...interface{}) *dbus.Call {
	if f.call == nil {
		return &dbus.Call{Err: fmt.Errorf("fakeObject(%s): unexpected Call(%s)", f.path, method)}
	}
	return f.call(method, args)
}

func (f *fakeObject) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	return f.Call(method, flags, args...)
}
func (f *fakeObject) Go(string, dbus.Flags, chan *dbus.Call, ...interface{}) *dbus.Call {
	panic("fakeObject: Go not supported")
}
func (f *fakeObject) GoWithContext(context.Context, string, dbus.Flags, chan *dbus.Call, ...interface{}) *dbus.Call {
	panic("fakeObject: GoWithContext not supported")
}
func (f *fakeObject) AddMatchSignal(string, string, ...dbus.MatchOption) *dbus.Call {
	panic("fakeObject: AddMatchSignal not supported")
}
func (f *fakeObject) RemoveMatchSignal(string, string, ...dbus.MatchOption) *dbus.Call {
	panic("fakeObject: RemoveMatchSignal not supported")
}

func (f *fakeObject) GetProperty(p string) (dbus.Variant, error) {
	if f.prop == nil {
		return dbus.Variant{}, fmt.Errorf("fakeObject(%s): unexpected GetProperty(%s)", f.path, p)
	}
	return f.prop(p)
}
func (f *fakeObject) StoreProperty(string, interface{}) error {
	panic("fakeObject: StoreProperty not supported")
}
func (f *fakeObject) SetProperty(string, interface{}) error {
	panic("fakeObject: SetProperty not supported")
}
func (f *fakeObject) Destination() string   { return secretsDest }
func (f *fakeObject) Path() dbus.ObjectPath { return f.path }

// fakeBus routes SecretService's object(dest, path) lookups to per-path
// fakeObjects, and reports which paths were requested but not registered.
type fakeBus struct {
	t       *testing.T
	objects map[dbus.ObjectPath]*fakeObject
}

func newFakeBus(t *testing.T) *fakeBus {
	return &fakeBus{t: t, objects: map[dbus.ObjectPath]*fakeObject{}}
}

func (b *fakeBus) register(o *fakeObject) { b.objects[o.path] = o }

func (b *fakeBus) objectFunc() objectFunc {
	return func(dest string, path dbus.ObjectPath) dbus.BusObject {
		if o, ok := b.objects[path]; ok {
			return o
		}
		b.t.Fatalf("fakeBus: no object registered for path %s", path)
		return nil
	}
}

func newTestService(bus *fakeBus) *SecretService {
	return &SecretService{
		conn:    &dbus.Conn{}, // non-nil so connect() is a no-op
		session: "/org/freedesktop/secrets/session/s1",
		object:  bus.objectFunc(),
	}
}

func searchItemsCall(unlocked, locked []dbus.ObjectPath) func(string, []interface{}) *dbus.Call {
	return func(method string, args []interface{}) *dbus.Call {
		if method != ifaceService+".SearchItems" {
			return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
		}
		return &dbus.Call{Body: []interface{}{unlocked, locked}}
	}
}

func TestSecretService_GetUsername(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(name string) (dbus.Variant, error) {
			if name != itemAttrsProp {
				return dbus.Variant{}, fmt.Errorf("unexpected property %s", name)
			}
			return dbus.MakeVariant(map[string]string{attrService: "svc", attrUsername: "alice"}), nil
		},
	})

	s := newTestService(bus)
	got, err := s.GetUsername("svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "alice" {
		t.Fatalf("got %q, want alice", got)
	}
}

func TestSecretService_GetUsername_EmptyAccountAttributeMissing(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			// account was "" on Add: attribute present, empty value.
			return dbus.MakeVariant(map[string]string{attrService: "svc", attrUsername: ""}), nil
		},
	})

	s := newTestService(bus)
	got, err := s.GetUsername("svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

func TestSecretService_GetUsername_NotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall(nil, nil),
	})

	s := newTestService(bus)
	_, err := s.GetUsername("svc")
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ErrNotFound, got %v (%T)", err, err)
	}
}

func TestSecretService_GetPassword(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// resolveItem now has to read Attributes to confirm ownership (see
		// isOwnItem) before GetPassword ever calls GetSecret.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc", attrUsername: "alice"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".GetSecret" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			sessionArg, _ := args[0].(dbus.ObjectPath)
			if sessionArg != "/org/freedesktop/secrets/session/s1" {
				return &dbus.Call{Err: fmt.Errorf("unexpected session arg %v", sessionArg)}
			}
			return &dbus.Call{Body: []interface{}{secretValue{
				Session:     sessionArg,
				Value:       []byte("hunter2"),
				ContentType: "text/plain",
			}}}
		},
	})

	s := newTestService(bus)
	got, err := s.GetPassword("svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q, want hunter2", got)
	}
}

func TestSecretService_GetPassword_NotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall(nil, nil),
	})

	s := newTestService(bus)
	_, err := s.GetPassword("svc")
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ErrNotFound, got %v (%T)", err, err)
	}
}

// TestSecretService_GetPassword_ForeignSchemaItemIsNotFound is the HIGH
// severity fix from the PR #29 security review: an item that matches on the
// "service" attribute but was written by a different local application (a
// different xdg:schema) must never be disclosed via GetPassword. It must
// behave exactly as if SearchItems had never returned it — i.e. *ErrNotFound
// — not merely "found but rejected" with some other error.
func TestSecretService_GetPassword_ForeignSchemaItemIsNotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{
				attrService: "svc",
				attrSchema:  "com.example.other.Schema",
			}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			return &dbus.Call{Err: fmt.Errorf("foreign item /item/1 must never be read, got %s", method)}
		},
	})

	s := newTestService(bus)
	_, err := s.GetPassword("svc")
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ErrNotFound for a foreign-schema item, got %v (%T)", err, err)
	}
}

func TestSecretService_GetPassword_UnlocksLockedItem(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: func(method string, args []interface{}) *dbus.Call {
			switch method {
			case ifaceService + ".SearchItems":
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath(nil), []dbus.ObjectPath{"/item/1"}}}
			case ifaceService + ".Unlock":
				paths, _ := args[0].([]dbus.ObjectPath)
				if len(paths) != 1 || paths[0] != "/item/1" {
					return &dbus.Call{Err: fmt.Errorf("unexpected Unlock args %v", args)}
				}
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath{"/item/1"}, rootPath}}
			default:
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// filterOwnItems reads Attributes on the locked candidate too (see
		// searchItems), before it ever gets to Unlock.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".GetSecret" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			return &dbus.Call{Body: []interface{}{secretValue{Value: []byte("unlocked-secret")}}}
		},
	})

	s := newTestService(bus)
	got, err := s.GetPassword("svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "unlocked-secret" {
		t.Fatalf("got %q, want unlocked-secret", got)
	}
}

// TestSecretService_GetPassword_ReadFailureAfterResolveIsNotErrNotFound
// covers CRITICAL 1 from the PR #29 review: resolveItem already found this
// item, so a subsequent GetSecret failure is never "not found" — it must
// not collapse to *ErrNotFound, because cmd/set.go treats *ErrNotFound as
// "safe to overwrite without confirmation".
func TestSecretService_GetPassword_ReadFailureAfterResolveIsNotErrNotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// resolveItem reads Attributes to confirm ownership before returning
		// this item, so this must succeed for the test to reach GetSecret.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".GetSecret" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			return &dbus.Call{Err: dbus.Error{
				Name: "org.freedesktop.DBus.Error.NoReply",
				Body: []interface{}{"item re-locked between resolve and read"},
			}}
		},
	})

	s := newTestService(bus)
	_, err := s.GetPassword("svc")
	if err == nil {
		t.Fatal("expected error")
	}
	var nf *ErrNotFound
	if errors.As(err, &nf) {
		t.Fatalf("a read failure on an item resolveItem already found must not be *ErrNotFound, got %v", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected the wrapped error to be *ErrUnavailable, got %v (%T)", err, err)
	}
}

// TestSecretService_GetUsername_ReadFailureAfterResolveIsNotErrNotFound is
// the GetUsername counterpart of the above: itemAttributes failing after a
// successful resolveItem must not be reported as "not found" either.
func TestSecretService_GetUsername_ReadFailureAfterResolveIsNotErrNotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.Variant{}, fmt.Errorf("transport fault")
		},
	})

	s := newTestService(bus)
	_, err := s.GetUsername("svc")
	if err == nil {
		t.Fatal("expected error")
	}
	var nf *ErrNotFound
	if errors.As(err, &nf) {
		t.Fatalf("a read failure on an item resolveItem already found must not be *ErrNotFound, got %v", err)
	}
}

// TestSecretService_GetPassword_UnlockSucceedsButItemStillMissing covers the
// resolveItem branch where Unlock returns without error but the target item
// is absent from its result set (e.g. the prompt was dismissed). The item
// is known to exist and known to be locked, so this must not be reported as
// *ErrNotFound.
func TestSecretService_GetPassword_UnlockSucceedsButItemStillMissing(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: func(method string, args []interface{}) *dbus.Call {
			switch method {
			case ifaceService + ".SearchItems":
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath(nil), []dbus.ObjectPath{"/item/1"}}}
			case ifaceService + ".Unlock":
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath{}, rootPath}}
			default:
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// filterOwnItems (called from searchItems) reads Attributes on the
		// locked candidate to confirm ownership before Unlock is ever tried.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
	})

	s := newTestService(bus)
	_, err := s.GetPassword("svc")
	if err == nil {
		t.Fatal("expected error")
	}
	var nf *ErrNotFound
	if errors.As(err, &nf) {
		t.Fatalf("a known-to-exist, known-to-be-locked item must not report *ErrNotFound, got %v", err)
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *ErrUnavailable, got %v (%T)", err, err)
	}
}

// TestSecretService_Unlock_BadPromptResultType covers the case where the
// Completed signal's result variant does not assert to []dbus.ObjectPath.
// Silently keeping the pre-prompt (empty) unlocked set here would report a
// prompt the user successfully completed as "not found".
func TestSecretService_Unlock_BadPromptResultType(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: func(method string, args []interface{}) *dbus.Call {
			switch method {
			case ifaceService + ".SearchItems":
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath(nil), []dbus.ObjectPath{"/item/1"}}}
			case ifaceService + ".Unlock":
				return &dbus.Call{Body: []interface{}{[]dbus.ObjectPath(nil), dbus.ObjectPath("/prompt/1")}}
			default:
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// filterOwnItems (called from searchItems) reads Attributes on the
		// locked candidate to confirm ownership before Unlock is ever tried.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
	})

	s := newTestService(bus)
	s.prompt = func(dbus.ObjectPath) (dbus.Variant, error) {
		// Wrong shape: a real Secret Service Unlock prompt's Completed
		// result is []dbus.ObjectPath, not a bool.
		return dbus.MakeVariant(true), nil
	}

	_, err := s.GetPassword("svc")
	if err == nil {
		t.Fatal("expected error")
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *ErrUnavailable for an unrecognized prompt result, got %v (%T)", err, err)
	}
}

func TestSecretService_Add(t *testing.T) {
	bus := newFakeBus(t)
	var gotProps map[string]dbus.Variant
	var gotSecret secretValue
	var gotReplace bool
	bus.register(&fakeObject{
		path: defaultAlias,
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceCollection+".CreateItem" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			gotProps, _ = args[0].(map[string]dbus.Variant)
			gotSecret, _ = args[1].(secretValue)
			gotReplace, _ = args[2].(bool)
			return &dbus.Call{Body: []interface{}{dbus.ObjectPath("/item/1"), rootPath}}
		},
	})

	s := newTestService(bus)
	if err := s.Add("svc", "alice", "hunter2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotReplace {
		t.Fatal("expected replace=true")
	}
	if string(gotSecret.Value) != "hunter2" {
		t.Fatalf("password not passed as secret value: %q", gotSecret.Value)
	}
	if gotSecret.Session != s.session {
		t.Fatalf("secret session mismatch: %v != %v", gotSecret.Session, s.session)
	}
	label := gotProps[itemLabelProp].Value().(string)
	if label != "svc (alice)" {
		t.Fatalf("got label %q, want %q", label, "svc (alice)")
	}
	attrs := gotProps[itemAttrsProp].Value().(map[string]string)
	if attrs[attrService] != "svc" || attrs[attrUsername] != "alice" {
		t.Fatalf("unexpected attributes: %v", attrs)
	}
	// CRITICAL (PR #29 security review): every item this backend creates
	// must be stamped with its own xdg:schema so later reads can tell it
	// apart from another local application's item that happens to share the
	// "service"/"username" attribute convention (see isOwnItem).
	if attrs[attrSchema] != appSchema {
		t.Fatalf("got xdg:schema %q, want %q", attrs[attrSchema], appSchema)
	}
}

func TestSecretService_Add_NoAccountOmitsFromLabel(t *testing.T) {
	bus := newFakeBus(t)
	var gotLabel string
	bus.register(&fakeObject{
		path: defaultAlias,
		call: func(method string, args []interface{}) *dbus.Call {
			props, _ := args[0].(map[string]dbus.Variant)
			gotLabel = props[itemLabelProp].Value().(string)
			return &dbus.Call{Body: []interface{}{dbus.ObjectPath("/item/1"), rootPath}}
		},
	})

	s := newTestService(bus)
	if err := s.Add("svc", "", "pw"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotLabel != "svc" {
		t.Fatalf("got label %q, want %q", gotLabel, "svc")
	}
}

func TestSecretService_Add_Error(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: defaultAlias,
		call: func(string, []interface{}) *dbus.Call {
			return &dbus.Call{Err: dbus.Error{
				Name: "org.freedesktop.DBus.Error.AccessDenied",
				Body: []interface{}{"prompt dismissed"},
			}}
		},
	})

	s := newTestService(bus)
	err := s.Add("svc", "alice", "pw")
	if err == nil {
		t.Fatal("expected error")
	}
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected the wrapped error to be *ErrUnavailable, got %v (%T)", err, err)
	}
}

func TestSecretService_Delete(t *testing.T) {
	var deletedPaths []dbus.ObjectPath
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1"}, []dbus.ObjectPath{"/item/2"}),
	})
	deleteHandler := func(path dbus.ObjectPath) func(string, []interface{}) *dbus.Call {
		return func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".Delete" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			deletedPaths = append(deletedPaths, path)
			return &dbus.Call{Body: []interface{}{rootPath}}
		}
	}
	// searchItems (via filterOwnItems) reads Attributes on every candidate,
	// locked or not, to confirm ownership before Delete ever touches it.
	ownAttrs := func(string) (dbus.Variant, error) {
		return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
	}
	bus.register(&fakeObject{path: "/item/1", call: deleteHandler("/item/1"), prop: ownAttrs})
	bus.register(&fakeObject{path: "/item/2", call: deleteHandler("/item/2"), prop: ownAttrs})

	s := newTestService(bus)
	if err := s.Delete("svc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deletedPaths) != 2 {
		t.Fatalf("expected both matching items deleted, got %v", deletedPaths)
	}
}

// TestSecretService_Delete_ExcludesForeignSchemaItem covers the Delete side
// of the PR #29 security review: an item that shares the "service" attribute
// with what's being deleted, but carries a different application's
// xdg:schema, must never be touched — Delete must behave as if that item did
// not exist at all, not merely skip it after finding it.
func TestSecretService_Delete_ExcludesForeignSchemaItem(t *testing.T) {
	var deletedPaths []dbus.ObjectPath
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall([]dbus.ObjectPath{"/item/1", "/item/2"}, nil),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".Delete" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			deletedPaths = append(deletedPaths, "/item/1")
			return &dbus.Call{Body: []interface{}{rootPath}}
		},
	})
	bus.register(&fakeObject{
		path: "/item/2",
		// A foreign application's item that happens to share the "service"
		// attribute value, but tags itself with its own xdg:schema.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc", attrSchema: "com.example.other.Schema"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			return &dbus.Call{Err: fmt.Errorf("foreign item /item/2 must never be called, got %s", method)}
		},
	})

	s := newTestService(bus)
	if err := s.Delete("svc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deletedPaths) != 1 || deletedPaths[0] != "/item/1" {
		t.Fatalf("expected only /item/1 to be deleted, got %v", deletedPaths)
	}
}

// TestSecretService_Delete_LockedItemFailureHintsUnlock covers the
// Delete/locked-item mismatch from the PR #29 review: Delete does not
// unlock locked items first, so if a provider's Item.Delete call fails on
// one, the error must call out that the item is locked rather than
// surfacing a generic "backend down" message.
func TestSecretService_Delete_LockedItemFailureHintsUnlock(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall(nil, []dbus.ObjectPath{"/item/1"}),
	})
	bus.register(&fakeObject{
		path: "/item/1",
		// filterOwnItems reads Attributes on the locked candidate to confirm
		// ownership before Delete ever calls Item.Delete on it.
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "svc"}), nil
		},
		call: func(method string, args []interface{}) *dbus.Call {
			if method != ifaceItem+".Delete" {
				return &dbus.Call{Err: fmt.Errorf("unexpected method %s", method)}
			}
			return &dbus.Call{Err: dbus.Error{
				Name: "org.freedesktop.DBus.Error.AccessDenied",
				Body: []interface{}{"item is locked"},
			}}
		},
	})

	s := newTestService(bus)
	err := s.Delete("svc")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected the error to explain that the item is locked, got %v", err)
	}
}

func TestSecretService_Delete_NotFound(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		call: searchItemsCall(nil, nil),
	})

	s := newTestService(bus)
	err := s.Delete("svc")
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ErrNotFound, got %v (%T)", err, err)
	}
}

func TestSecretService_List(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		prop: func(name string) (dbus.Variant, error) {
			if name != ifaceService+".Collections" {
				return dbus.Variant{}, fmt.Errorf("unexpected property %s", name)
			}
			return dbus.MakeVariant([]dbus.ObjectPath{"/collection/login", "/collection/session"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/collection/login",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant([]dbus.ObjectPath{"/item/1", "/item/2"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/collection/session",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant([]dbus.ObjectPath{"/item/3", "/item/4"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "zeta", attrUsername: "a"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/2",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "alpha", attrUsername: "b"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/3",
		prop: func(string) (dbus.Variant, error) {
			// Duplicate service name ("alpha") in a different collection, with
			// no xdg:schema at all — a legacy item this backend itself wrote
			// before the fix, still recognized as "own" by isOwnItem, so this
			// exercises dedupSorted collapsing it with /item/2's "alpha".
			return dbus.MakeVariant(map[string]string{attrService: "alpha"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/4",
		prop: func(string) (dbus.Variant, error) {
			// CRITICAL (PR #29 security review): an unrelated local
			// application's item that happens to use the same "service"
			// attribute convention, but tags itself with its own xdg:schema.
			// isOwnItem must recognize this as foreign, and List must exclude
			// it entirely rather than disclose it.
			return dbus.MakeVariant(map[string]string{attrService: "gamma", attrSchema: "com.example.other.Schema"}), nil
		},
	})

	s := newTestService(bus)
	got, err := s.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"alpha", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, n := range got {
		if n == "gamma" {
			t.Fatalf("expected the foreign-schema item's service (gamma) to be excluded, got %v", got)
		}
	}
}

// TestSecretService_List_CollectionPropertyErrorFailsWholeCall covers
// CRITICAL 3 from the PR #29 review: on PR #24 the project deliberately
// chose to fail List() outright over returning a partial list, on the
// grounds that a truncated list presented as complete is the same bug
// wearing a smaller hat. A collection whose Items property errors must
// fail the whole call, not be silently skipped.
func TestSecretService_List_CollectionPropertyErrorFailsWholeCall(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		prop: func(name string) (dbus.Variant, error) {
			if name != ifaceService+".Collections" {
				return dbus.Variant{}, fmt.Errorf("unexpected property %s", name)
			}
			return dbus.MakeVariant([]dbus.ObjectPath{"/collection/login", "/collection/broken"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/collection/login",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant([]dbus.ObjectPath{"/item/1"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "alpha", attrUsername: "a"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/collection/broken",
		prop: func(string) (dbus.Variant, error) {
			return dbus.Variant{}, fmt.Errorf("collection temporarily unreadable (e.g. a race right after activation)")
		},
	})

	s := newTestService(bus)
	got, err := s.List()
	if err == nil {
		t.Fatalf("expected List to fail when a collection cannot be enumerated, got %v (no error)", got)
	}
}

// TestSecretService_List_ItemAttributesErrorFailsWholeCall is the
// item-level counterpart: a single item's Attributes property erroring
// must also fail the whole call rather than being skipped.
func TestSecretService_List_ItemAttributesErrorFailsWholeCall(t *testing.T) {
	bus := newFakeBus(t)
	bus.register(&fakeObject{
		path: secretsPath,
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant([]dbus.ObjectPath{"/collection/login"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/collection/login",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant([]dbus.ObjectPath{"/item/1", "/item/2"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/1",
		prop: func(string) (dbus.Variant, error) {
			return dbus.MakeVariant(map[string]string{attrService: "alpha"}), nil
		},
	})
	bus.register(&fakeObject{
		path: "/item/2",
		prop: func(string) (dbus.Variant, error) {
			return dbus.Variant{}, fmt.Errorf("attribute read failed")
		},
	})

	s := newTestService(bus)
	got, err := s.List()
	if err == nil {
		t.Fatalf("expected List to fail when an item's attributes can't be read, got %v (no error)", got)
	}
}

func TestSecretService_Edit_ReturnsError(t *testing.T) {
	s := NewSecretService()
	if err := s.Edit(); err == nil {
		t.Fatal("expected Edit to return an error on Linux")
	}
}

func TestClassifyBusError_ServiceUnknown(t *testing.T) {
	err := classifyBusError(dbus.Error{
		Name: "org.freedesktop.DBus.Error.ServiceUnknown",
		Body: []interface{}{"The name org.freedesktop.secrets was not provided by any .service files"},
	})
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *ErrUnavailable, got %v (%T)", err, err)
	}
	if unavailable.Reason == "" {
		t.Fatal("expected a non-empty, actionable reason")
	}
}

func TestClassifyBusError_Other(t *testing.T) {
	err := classifyBusError(errors.New("boom"))
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *ErrUnavailable, got %v (%T)", err, err)
	}
}

func TestBuildItemLabel(t *testing.T) {
	if got := buildItemLabel("svc", ""); got != "svc" {
		t.Fatalf("got %q, want svc", got)
	}
	if got := buildItemLabel("svc", "alice"); got != "svc (alice)" {
		t.Fatalf("got %q, want svc (alice)", got)
	}
}

// TestIsOwnItem covers the three cases isOwnItem's migration decision (see
// its doc comment) is built around: an exact appSchema match, a missing
// xdg:schema attribute (a legacy item from before this fix), and a
// different application's schema.
func TestIsOwnItem(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]string
		want  bool
	}{
		{"exact schema match", map[string]string{attrSchema: appSchema}, true},
		{"schema attribute absent (legacy item)", map[string]string{attrService: "svc"}, true},
		{"schema attribute present but empty", map[string]string{attrSchema: ""}, true},
		{"different application's schema", map[string]string{attrSchema: "com.example.other.Schema"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isOwnItem(c.attrs); got != c.want {
				t.Fatalf("isOwnItem(%v) = %v, want %v", c.attrs, got, c.want)
			}
		})
	}
}

func TestPickItem(t *testing.T) {
	if _, ok := pickItem(nil); ok {
		t.Fatal("expected no item for empty candidates")
	}
	item, ok := pickItem([]dbus.ObjectPath{"/a", "/b"})
	if !ok || item != "/a" {
		t.Fatalf("got (%v, %v), want (/a, true)", item, ok)
	}
}

func TestDedupSorted(t *testing.T) {
	got := dedupSorted([]string{"b", "a", "b", "a", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if dedupSorted(nil) != nil {
		t.Fatal("expected nil for empty input")
	}
}
