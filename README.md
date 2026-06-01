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

## Installation

### macOS

```sh
go install github.com/asnowfix/secret@latest
```

Or download the `darwin` archive from the [releases page](https://github.com/asnowfix/secret/releases) and place the binary on your `PATH`.

### Windows

```powershell
winget install asnowfix.secret
```

Or via [Scoop](https://scoop.sh):

```powershell
scoop bucket add asnowfix https://github.com/asnowfix/scoop-secret
scoop install secret
```

### WSL (Windows Subsystem for Linux)

The Linux `secret` binary auto-detects WSL and trampolines every command to `secret.exe` on the Windows host. Two steps are required:

**1. Install `secret.exe` on the Windows host** (from a PowerShell or cmd prompt, not inside WSL):

```powershell
winget install asnowfix.secret
# or: scoop bucket add asnowfix https://github.com/asnowfix/scoop-secret && scoop install secret
```

**2. Install the Linux `secret` binary inside WSL:**

If Go is not already installed:

```sh
sudo snap install go --classic
```

Then install `secret`:

```sh
go install github.com/asnowfix/secret@latest
```

Or download the `linux` archive from the [releases page](https://github.com/asnowfix/secret/releases) and place the binary on your `PATH`.

After that, `secret` works transparently from your WSL shell — credentials are stored in the Windows Credential Manager on the host.

If `secret.exe` is not found on the Windows `PATH`, `secret` will print an error with installation instructions.

## Usage

```sh
secret login <service>          # retrieve account/username
secret password <service>       # retrieve password
secret set <service> [account] <password>  # store credential (overwrites if exists)
secret delete <service>         # remove credential
secret edit                     # open native UI
```

Aliases: `username` and `client_id` map to `login`; `client_secret` maps to `password`.

## Backends

| Backend | Platform | Status |
|---------|----------|--------|
| macOS Keychain (`/usr/bin/security`) | macOS | Implemented |
| Windows Credential Manager | Windows | Implemented |
| WSL trampoline → `secret.exe` | WSL | Implemented |
| Passwords.app (Security framework) | macOS | Planned |
| GNOME libsecret / Secret Service | Linux | Planned |
| KeePassXC | macOS, Linux, Windows | Planned |

### Windows Credential Manager

Credentials are stored as **Generic** entries (`CRED_TYPE_GENERIC`) with machine-level persistence (`CRED_PERSIST_LOCAL_MACHINE`), making them available to all processes on the machine under the current user account.

The implementation calls `Advapi32.dll` directly via Go syscalls — no cgo, no third-party library. Passwords are stored as UTF-16LE blobs, matching Windows' native string encoding for credential data.

`secret edit` opens the built-in Credential Manager UI (`control.exe /name Microsoft.CredentialManager`) where stored entries are visible under **Windows Credentials → Generic Credentials**.

## Building

```sh
go build .        # local binary
go install .      # install to $GOPATH/bin
```

Requires Go 1.25+. For full contributor setup (Windows winget commands, local CI parity, PR workflow) see [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting Issues

File a bug report or feature request at [github.com/asnowfix/secret/issues/new/choose](https://github.com/asnowfix/secret/issues/new/choose). When reporting a bug, include the output of `secret version` and your OS version.
