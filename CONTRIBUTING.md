# Contributing to secret

This guide covers setting up a local development environment on Windows or macOS, building and testing the project, and submitting a pull request. For architecture details and AI agent guidance see [AGENTS.md](AGENTS.md).

## Prerequisites — macOS

Install the following tools via [Homebrew](https://brew.sh):

```sh
brew install go               # Go 1.25+ (CI uses 1.25; any later release works)
brew install gh               # GitHub CLI — used for cloning and creating PRs
brew install goreleaser       # for release dry-runs
```

`git` ships with Xcode Command Line Tools. If not already installed, run:

```sh
xcode-select --install
```

After installation, verify the tools are on your `PATH`:

```sh
go version && git --version && gh --version && goreleaser --version
```

No extra C toolchain configuration is required — the macOS backend calls the built-in `/usr/bin/security` CLI via `os/exec` (`CGO_ENABLED=0`).

## Prerequisites — Windows

Install the following tools via [winget](https://learn.microsoft.com/windows/package-manager/winget/):

```powershell
winget install --id GoLang.Go -e          # Go 1.25+ (CI uses 1.25; any later release works)
winget install --id Git.Git -e
winget install --id GitHub.cli -e         # gh — used for cloning and creating PRs
winget install --id goreleaser.goreleaser -e  # goreleaser — for release dry-runs
```

Restart your terminal after installation so that `go`, `git`, `gh`, and `goreleaser` are on your `PATH`.

No C compiler or CGO toolchain is required — the Windows backend calls `Advapi32.dll` via Go syscalls (`CGO_ENABLED=0`).

## Clone the repository

```sh
gh repo clone asnowfix/secret
cd secret
```

Or with plain git:

```sh
git clone https://github.com/asnowfix/secret.git
cd secret
```

## Build & run

```sh
go build .        # produces ./secret (or secret.exe on Windows)
go install .      # installs to $GOPATH/bin
go run . <cmd>    # run directly without installing
```

Build with version injection (matches what a tagged release reports):

```sh
go build -ldflags "-X github.com/asnowfix/secret/cmd.version=$(git describe --tags --always --dirty)" .
./secret version
```

Cross-compile sanity check — all three platforms must build cleanly because the CI matrix covers Linux, macOS, and Windows:

```sh
GOOS=darwin go build ./...
GOOS=linux go build ./...
GOOS=windows go build ./...
```

## Local CI parity

Run the same three commands that `.github/workflows/ci.yml` runs on every PR before pushing:

```sh
go build ./...
go vet ./...
go test ./...
```

There is no test suite yet, so `go test` passes trivially. Adding tests alongside your change is welcome but not required.

## Manual smoke test (Windows)

```sh
secret set my-service my-account my-password
secret login my-service        # should print: my-account
secret password my-service     # should print: my-password
secret edit                    # opens Windows Credential Manager UI
secret delete my-service
secret version
```

## Manual smoke test (macOS)

```sh
secret set my-service my-account my-password
secret login my-service        # should print: my-account
secret password my-service     # should print: my-password
secret edit                    # opens Keychain Access.app
secret delete my-service
secret version
```

The macOS backend stores entries in the login keychain via `/usr/bin/security`. You can inspect them in **Keychain Access.app** (opened by `secret edit`) under the login keychain to confirm the entry was created and removed correctly.

## Publishing a release

Releases are fully automated via `.github/workflows/release.yml`. Pushing a version tag triggers goreleaser, which:

1. Builds binaries for Linux, macOS, and Windows.
2. Creates a GitHub Release and uploads the archives.
3. Commits a Scoop manifest to [`asnowfix/scoop-secret`](https://github.com/asnowfix/scoop-secret).
4. Opens a PR against [`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs) via the [`asnowfix/winget-pkgs`](https://github.com/asnowfix/winget-pkgs) fork.

Steps 3 and 4 write to repositories outside `asnowfix/secret`, so `GITHUB_TOKEN` (which is scoped to the current repo) is not sufficient. The workflow uses a `GH_PAT` secret instead.

### Setting up GH_PAT

goreleaser needs a token with **Contents: Read & Write** and **Pull requests: Read & Write** access to both `asnowfix/scoop-secret` and `asnowfix/winget-pkgs`.

**Fine-grained PAT — current limitation:** GitHub's fine-grained PAT UI does not currently allow selecting forked repositories (such as `winget-pkgs`) as individual resource targets. Until that restriction is lifted, use a **classic PAT** instead:

1. Go to **github.com/settings/tokens** → **Generate new token (classic)**.
2. Select the `repo` scope (full repository access).
3. Set an expiry appropriate for your release cadence.
4. Copy the generated token.
5. In the `asnowfix/secret` repository go to **Settings → Secrets and variables → Actions → New repository secret**.
6. Name: `GH_PAT`, value: the token you copied.

Once GitHub lifts the fine-grained PAT restriction on forks, you can replace the classic token with a fine-grained one scoped only to `asnowfix/scoop-secret` and `asnowfix/winget-pkgs`.

### Triggering a release

```sh
git tag v1.2.3
git push origin v1.2.3
```

The CI job runs goreleaser and handles everything else. The winget PR is reviewed and merged by Microsoft's automated validation pipeline (typically within a few hours).

## Release dry-run (optional)

Before tagging a release, verify that the GoReleaser pipeline still works:

```sh
goreleaser check                                       # validate .goreleaser.yaml
goreleaser release --snapshot --clean --skip=publish   # build all artefacts without publishing
# inspect ./dist/ for archives and checksums.txt
```

## Creating a pull request

1. Create a branch from `main`:
   ```sh
   git checkout -b <topic>
   ```
   Branch names in this repo are short and descriptive: `worktree-cmd-version`, `windows-credential-manager`.

2. Commit your changes. **Policy from [AGENTS.md](AGENTS.md):**
   - Do NOT include `Co-Authored-By` trailers.
   - Do NOT include "Generated with Claude Code" strings.

3. Open a PR with the GitHub CLI:
   ```sh
   gh pr create --fill
   ```
   `--fill` pre-populates the PR body from `.github/PULL_REQUEST_TEMPLATE.md`. Fill in all sections before submitting.

4. Wait for CI green on both `windows-latest` and `macos-latest` before requesting review.
