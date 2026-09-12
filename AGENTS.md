# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## Build & Run

```sh
go build .          # produces ./secret
go install .        # installs to $GOPATH/bin
go run . <command>  # run without installing
```

Cross-compile check (no tests yet):
```sh
GOOS=linux go build ./...
GOOS=windows go build ./...
```

## Architecture

This is a Cobra+Viper CLI (`main.go` → `cmd/` → `backend/`) that abstracts platform-native secret stores behind a single `backend.Backend` interface.

**Key design decisions:**

- **Backend availability is compile-time, selection is also runtime-overridable**: `cmd/backend_darwin.go`, `cmd/backend_linux.go`, `cmd/backend_windows.go` each provide `selectBackend() (backend.Backend, error)` gated by `//go:build` tags — which backends exist in a given binary is still fixed at compile time, and new backends for a specific OS still go in a file with the matching build tag. Within a build, `selectBackend()` reads the `SECRET_BACKEND` env var (via `viper.GetString("backend")`; `cmd/root.go`'s `init()` sets `SetEnvPrefix("SECRET")` + `AutomaticEnv()`) to pick among the backends available on that platform, defaulting to the platform default when unset and erroring on a value this platform does not recognise (see issue #7 and `cmd/backend_common.go`'s `errUnrecognisedBackend`). On macOS, `--passwords-app` still wins over `SECRET_BACKEND` when both are given.
- **The macOS Keychain backend shells out to `/usr/bin/security`** rather than using cgo. This preserves ACL behavior (the `-T /usr/bin/security` flag grants non-interactive access).
- **Backend interface** (`backend/backend.go`): all backends implement `IsAvailable`, `GetUsername`, `GetPassword`, `Add`, `Delete`, `Edit`, `List`. Return `*ErrNotFound` or `*ErrUnavailable` for typed error handling; `List` may additionally return `*ErrNotSupported` for backends that cannot enumerate at all.
- **Runtime availability check**: `PersistentPreRunE` in the root command calls `b.IsAvailable()` before any subcommand runs (guards against locked keychains, missing daemons, etc.).

## Adding a New Backend

1. Create `backend/<name>.go` (with appropriate `//go:build` tag if platform-specific).
2. Implement `backend.Backend`.
3. Wire it into the appropriate `cmd/backend_<os>.go` file's `selectBackend()`, giving it a `SECRET_BACKEND` name (add it to that file's `<os>BackendNames` slice and to `knownBackendNames` in `cmd/backend_common.go` so unrecognised-value errors on other platforms can name it correctly).

## Running CI steps locally

Mirrors what the `ci.yml` workflow runs on every PR:

```sh
go build ./...
go vet ./...
go test ./...
```

Build with version injection (matches what a release binary reports):

```sh
go build -ldflags "-X github.com/asnowfix/secret/cmd.version=$(git describe --tags --always --dirty)" .
./secret version
```

Dry-run the release pipeline locally (requires `goreleaser` in PATH):

```sh
goreleaser check                                  # validate .goreleaser.yaml
goreleaser release --snapshot --clean --skip=publish  # build all release artefacts without publishing
# inspect ./dist/ for archives + checksums.txt
```

## Commits and PRs

Do NOT include `Co-Authored-By` trailers or `Generated with Claude Code` strings in commit messages or PR descriptions.
