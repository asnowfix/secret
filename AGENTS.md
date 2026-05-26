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

- **Platform selection is compile-time**: `cmd/backend_darwin.go`, `cmd/backend_linux.go`, `cmd/backend_windows.go` each provide `selectBackend()` gated by `//go:build` tags. New backends for a specific OS go in a file with the matching build tag.
- **The macOS Keychain backend shells out to `/usr/bin/security`** rather than using cgo. This preserves ACL behavior (the `-T /usr/bin/security` flag grants non-interactive access).
- **Backend interface** (`backend/backend.go`): all backends implement `IsAvailable`, `GetUsername`, `GetPassword`, `Add`, `Delete`, `Edit`. Return `*ErrNotFound` or `*ErrUnavailable` for typed error handling.
- **Runtime availability check**: `PersistentPreRunE` in the root command calls `b.IsAvailable()` before any subcommand runs (guards against locked keychains, missing daemons, etc.).

## Adding a New Backend

1. Create `backend/<name>.go` (with appropriate `//go:build` tag if platform-specific).
2. Implement `backend.Backend`.
3. Wire it into the appropriate `cmd/backend_<os>.go` file's `selectBackend()`.

## Commits and PRs

Do NOT include `Co-Authored-By` trailers or `Generated with Claude Code` strings in commit messages or PR descriptions.
