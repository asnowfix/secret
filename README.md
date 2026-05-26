# secret

A unified CLI that delegates to the platform's native secret store. One command, any desktop.

## Objective

Provide a single `secret` binary that works identically across macOS, Linux, and Windows by abstracting over each platform's built-in credential manager. Scripts, shell profiles, and automation tools call `secret` without caring which backend is active.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   CLI (Cobra)                    │
│  secret login|password|add|delete|edit <service> │
└────────────────────────┬────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────┐
│              backend.Backend interface           │
│  IsAvailable · GetUsername · GetPassword         │
│  Add · Delete · Edit                            │
└────┬───────────┬───────────┬───────────┬────────┘
     │           │           │           │
     ▼           ▼           ▼           ▼
 Keychain    libsecret   Win Cred    KeePassXC
 (macOS)     (Linux)     (Windows)   (cross-platform)
```

Backend selection is compile-time via Go build tags (`darwin`, `linux`, `windows`), with runtime override planned via `SECRET_BACKEND` env var.

## Usage

```sh
secret login <service>          # retrieve account/username
secret password <service>       # retrieve password
secret add <service> [account] <password>  # store credential
secret delete <service>         # remove credential
secret edit                     # open native UI
```

Aliases: `username` and `client_id` map to `login`; `client_secret` maps to `password`.

## Backends

| Backend | Platform | Status |
|---------|----------|--------|
| macOS Keychain (`/usr/bin/security`) | macOS | Implemented |
| Passwords.app (Security framework) | macOS | Planned |
| GNOME libsecret / Secret Service | Linux | Planned |
| Windows Credential Manager | Windows | Planned |
| KeePassXC | macOS, Linux, Windows | Planned |

## Building

```sh
go build .        # local binary
go install .      # install to $GOPATH/bin
```

Requires Go 1.25+.
