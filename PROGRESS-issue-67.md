# Progress: issue #67 (Keychain interactive timeout)

Scratch file, not part of the PR — delete before merge if it survives.

## Design source

Followed the design in https://github.com/asnowfix/secret/issues/67#issuecomment-5660584621
(read via `gh api repos/asnowfix/secret/issues/67/comments`, `gh issue view` returns nothing in
this environment).

## What I built

1. `backend/timeouts.go`: added `humanResponseTimeout = 2 * time.Minute`, doc comment carries the
   "bounds a person, not a machine" rationale, shared by both backends now.
2. `backend/libsecret.go`: `promptWaitTimeout` is now `= humanResponseTimeout` (alias), local doc
   comment kept per design, with a short addendum explaining the alias.
3. `backend/keychain.go`:
   - Added `golang.org/x/sys/unix` import (already a direct module dep via wincred.go's
     `golang.org/x/sys/windows`; no go.mod/go.sum change needed).
   - `isInteractive` package var (func value, not a plain func) probing
     `unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TIOCGETA)`. It's a var specifically so tests
     can swap it instead of depending on the real terminal state of the test runner.
   - `Keychain.promptTimeout time.Duration` field, zero meaning "same as timeout" (matches the
     existing `&Keychain{...}` test literals unchanged).
   - `NewKeychain()` sets `promptTimeout = humanResponseTimeout` when `isInteractive()` is true.
   - Split `runSecurity` (unchanged behaviour, machine bound, only caller left is
     `show-keychain-info` via `IsAvailable`) from new `runSecurityPrompt` (falls back to
     `k.timeout` when `k.promptTimeout == 0`), both delegating to a shared `runSecurityBounded`.
   - Call sites moved to `runSecurityPrompt`: `findPassword` (both generic and internet), `Add`,
     `Delete` (both generic and internet), `List` (`dump-keychain`). `IsAvailable` kept on
     `runSecurity`.
   - `classifySecurityError` became a method (`k.classifySecurityError`) so its timeout branch can
     read `k.promptTimeout` and add a "stderr was not detected as a terminal" hint when the call
     that timed out had fallen back to the short bound. New `keychainPromptTimeoutReason` wraps the
     unmodified `keychainTimeoutReason` message with that optional hint.  `keychainTimeoutReason`
     itself (used only by `IsAvailable`/`keychainUnavailableReason`) is untouched — its call site
     cannot raise a dialog, so an interactivity hint there would explain nothing.
4. `backend/timeouts_test.go`: added `TestHumanResponseTimeoutExceedsExternalCallTimeout`
   (`humanResponseTimeout > externalCallTimeout`), the counterpart of
   `libsecret_test.go`'s `TestDbusCallTimeoutRespectsCap` check.
5. `backend/keychain_test.go`: new section "Interactivity and the prompt timeout (issue #67)"
   before the opt-in-live-keychain section:
   - `newHangingKeychainWithPromptTimeout` helper (short injected durations for both bounds, never
     anywhere near 2 minutes, never touches `isInteractive`/`NewKeychain`).
   - `TestNewKeychain_PromptTimeout`: swaps the `isInteractive` var, asserts the wiring. Not
     `t.Parallel()` since it mutates a package var.
   - `TestRunSecurityPrompt_PrefersPromptTimeoutOverTimeout`: proves a prompting call is bounded by
     `promptTimeout`, not `timeout`, using a hanging stand-in and elapsed-time bounds.
   - `TestRunSecurityPrompt_ZeroPromptTimeoutFallsBackToTimeout`: proves `promptTimeout == 0`
     behaves exactly like pre-#67 (bounded by `timeout`), and checks the message hint appears.
   - `TestIsAvailable_IgnoresPromptTimeout`: proves `show-keychain-info` ignores `promptTimeout`
     entirely, and the message hint does *not* appear there.
   - `TestKeychainPromptTimeoutReason_InteractiveOmitsTerminalHint`: converse message check.
   - Extended `TestSecurityBoundsRespectCap`'s doc comment to name the `promptTimeout`/
     `humanResponseTimeout` exemption explicitly, mirroring `TestDbusCallTimeoutRespectsCap`.

## Verification (macOS, GOROOT env var was stale — `unset GOROOT` needed before every `go` command
in this shell; go1.25.9 darwin/amd64 via `/usr/local/opt/go@1.25/bin/go` is what actually runs)

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `GOOS=linux go build ./...` — clean.
- `GOOS=windows go build ./...` — clean.
- `go test ./...` — all pass, ~8s (see full run before opening PR).
- New tests individually verified with `-v`, all PASS, none sleeps anywhere near 2 minutes
  (`shortTimeout`/`promptBound` constants are all <= 2s).

## Deviations / things flagged back to the issue rather than silently built

None found so far that contradict the design. Two things I want on record as *not* independently
re-litigated, because the issue explicitly asked me to flag disagreement rather than silently
comply, and I did not find grounds to disagree:

- stderr-vs-stdin/stdout for the interactivity probe: the reasoning in the design (stdin/stdout are
  the git-credential-protocol pipes even at an interactive terminal; stderr is what this codebase
  already uses to talk to the user, per `validateBackendEnvIgnoredByFlag`) holds up under
  implementation — nothing about wiring the probe surfaced a case where stderr misclassifies
  interactively.
- The accepted ssh regression (tty on stderr, nobody at the console, now waits up to 2 minutes
  instead of failing at 5s): implemented as designed, with the trade-off restated in code comments
  (`keychain.go`'s `runSecurityPrompt` doc comment and `timeouts.go`'s `humanResponseTimeout` doc
  comment) and in the PR description, so a reviewer can push back on it specifically.

## Open items before PR

- [ ] Run full `go test ./...` once more after this commit.
- [ ] Push branch.
- [ ] Open PR via `github-contributor` skill, targeting `v0.3.1`, per the issue's PR-description
      requirements.
