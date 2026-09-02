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
└────┬──────────┬──────────┬──────────┬───────────┘
     │          │          │          │
     ▼          ▼          ▼          ▼
Passwords.app  Keychain  Win Cred  libsecret
(macOS 15+)   (macOS,   (Windows)  (Linux,
              fallback)             planned)
```

Backend selection is compile-time via Go build tags (`darwin`, `linux`, `windows`). On macOS, `selectBackend()` prefers `PasswordsApp` when available and falls back to `Keychain`; pass `--keychain` / `-k` to force the fallback at runtime.

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

#### Scoop installed after WSL was already running

WSL takes a snapshot of the Windows `PATH` at launch. If you installed Scoop (or `secret`) after your WSL session was already open, WSL won't see Scoop's shims directory yet and `secret.exe` will appear missing.

First, make sure Scoop's shims directory is in your **permanent** Windows user `PATH` (from PowerShell):

```powershell
# Check — should print a line containing "scoop\shims"
[Environment]::GetEnvironmentVariable("Path", "User") -split ";" | Select-String "scoop"

# If missing, add it:
$old = [Environment]::GetEnvironmentVariable("Path", "User")
[Environment]::SetEnvironmentVariable("Path", "$old;$env:USERPROFILE\scoop\shims", "User")
```

Then restart WSL so it picks up the updated `PATH`:

```powershell
wsl --shutdown
```

Reopen your WSL terminal and verify:

```sh
which secret.exe
```

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
| Passwords.app (Security framework, cgo) | macOS 15+ | Implemented — default on macOS 15+ |
| macOS Keychain (`/usr/bin/security`) | macOS | Implemented — fallback on macOS < 15; selectable via `--keychain` |
| Windows Credential Manager | Windows | Implemented |
| WSL trampoline → `secret.exe` | WSL | Implemented |
| GNOME libsecret / Secret Service (D-Bus) | Linux | Implemented — unverified on a real desktop, see below |
| Passwords.app: Safari/iCloud credentials | macOS 15+ | Planned — requires code signing + entitlements ([#20](https://github.com/asnowfix/secret/issues/20)) |
| KeePassXC | macOS, Linux, Windows | Planned |

### macOS — Passwords.app (default on macOS 15+)

Calls `SecItemCopyMatching`, `SecItemAdd`, and `SecItemDelete` from the Security framework directly via cgo. Unlike the Keychain backend, it does not hardcode `login.keychain-db` — it searches the default keychain list, which includes iCloud-synced items.

Both `kSecClassGenericPassword` (by `kSecAttrService`) and `kSecClassInternetPassword` (by `kSecAttrServer`) are tried on reads and deletes, so browser-saved entries are returned alongside credentials added by `secret`. Writes always use `kSecClassGenericPassword`.

`secret edit` opens Passwords.app (`com.apple.Passwords`), which shows all credential types in one view.

> **Limitation**: credentials saved by Safari are stored in the data-protection keychain with access controls that block unsigned processes. `secret` can read and write credentials it manages itself; accessing Safari-saved credentials requires a signed binary with the `keychain-access-groups` entitlement ([#20](https://github.com/asnowfix/secret/issues/20)).

#### Forcing the Keychain backend on macOS

Pass `--keychain` / `-k` to any command to route it through the `login.keychain-db` backend instead:

```sh
secret -k password myservice
secret -k set myservice user pass
```

### macOS — Keychain (fallback / macOS < 15)

Shells out to `/usr/bin/security` targeting `~/Library/Keychains/login.keychain-db`. Used automatically on macOS < 15, or when `--keychain` is passed.

### Windows Credential Manager

Credentials are stored as **Generic** entries (`CRED_TYPE_GENERIC`) with machine-level persistence (`CRED_PERSIST_LOCAL_MACHINE`), making them available to all processes on the machine under the current user account.

The implementation calls `Advapi32.dll` directly via Go syscalls — no cgo, no third-party library. Passwords are stored as UTF-16LE blobs, matching Windows' native string encoding for credential data.

`secret edit` opens the built-in Credential Manager UI (`control.exe /name Microsoft.CredentialManager`) where stored entries are visible under **Windows Credentials → Generic Credentials**.

### Linux — GNOME libsecret / Secret Service (D-Bus)

Talks directly to the [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/) over D-Bus (`github.com/godbus/dbus/v5`), rather than shelling out to `secret-tool` or adopting a third-party keyring library — see the implementation PR for the full comparison. This is a generic client against the spec, not a GNOME-only integration, so it should in principle also work against KWallet's `ksecretd` (which implements the same D-Bus interface) — but that has never actually been run or tested, only `gnome-keyring-daemon` has.

Credentials are tagged with `service` and `username` attributes (the same convention Python's `keyring` SecretService backend uses), stored in the default collection, and readable by other Secret-Service-aware tools.

> **Not verified on a real desktop, and only partially verified against a real daemon at all**: the maintainer has no Linux machine with a GNOME/KDE session. This backend is exercised end-to-end in CI against a real `gnome-keyring-daemon`, headless, via `dbus-run-session` (see `.github/workflows/ci.yml` and `backend/libsecret_live_test.go`), which does confirm happy-path CRUD and single-collection enumeration genuinely work against a real daemon. But CI force-`--unlock`s the daemon before the test runs, so the entire Secret Service Prompt object protocol — the mechanism behind unlocking a locked item and behind interactive consent on `Add` — has never executed against any real implementation, not just its GUI-display aspect. Nor is any of this the same as a logged-in desktop session, where the keyring may already be unlocked via PAM at login or may prompt interactively. If you hit an issue on a real desktop, especially around unlocking or prompts, please report it.

`secret edit` has no native equivalent to open on Linux (there is no single credential-manager UI guaranteed to be installed the way there is on macOS/Windows) and returns an error suggesting `secret-tool` or a keyring GUI like Seahorse instead.

### WSL trampoline

On WSL, `secret` re-execs `secret.exe` on the Windows host (see [WSL](#wsl-windows-subsystem-for-linux) above) *before* considering the Linux Secret Service backend — WSL users get the Windows Credential Manager, not a WSL-local keyring, even if one happens to be running.

## Building

```sh
go build .        # local binary
go install .      # install to $GOPATH/bin
```

Requires Go 1.25+. For full contributor setup (Windows winget commands, local CI parity, PR workflow) see [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting Issues

File a bug report or feature request at [github.com/asnowfix/secret/issues/new/choose](https://github.com/asnowfix/secret/issues/new/choose). When reporting a bug, include the output of `secret version` and your OS version.
