package backend

import "time"

// maxExternalCallTimeout is the hard ceiling on how long this package will
// wait for any *machine* on the other end of an external call: the
// /usr/bin/security subprocess on macOS, a Secret Service provider on the
// D-Bus session bus on Linux, securityd behind the Security framework.
// Every such bound in this package must be <= this value, and the tests fail
// the build if one is not: TestExternalCallTimeoutRespectsCap on every
// platform, TestSecurityBoundsRespectCap on darwin,
// TestDbusCallTimeoutRespectsCap on linux.
//
// The cap is per call, not per command. A single CLI invocation composes
// several bounded calls — `secret password foo` on the Keychain backend runs
// IsAvailable, then a generic find, then an internet find — so the worst case
// a *user* can see is a multiple of this, not this. Bounding the command as a
// whole would be a different (and larger) change; what the cap guarantees is
// that no individual call can hang forever.
//
// It deliberately does not apply to a wait for a *person*. The distinction
// is the thing being waited on, not the wall-clock length: a machine that
// has not answered within a small multiple of its normal response time is
// not going to answer, whereas a human being asked to read a dialog and
// type a password reasonably needs longer. humanResponseTimeout below is
// the one deliberate wait-for-a-human duration in this package, currently
// reached two ways — libsecret.go's promptWaitTimeout (an alias for it, for
// a Secret Service unlock prompt) and keychain.go's Keychain.promptTimeout
// (set to it when a macOS keychain-unlock or ACL dialog is plausibly
// answerable) — and both are excluded from this cap on that ground.
//
// A GUI dialog on the machine side does not by itself make a call a
// wait-for-a-human: an unbounded SecItemCopyMatching behind a
// keychain-unlock or ACL authorization dialog (issue #37, #44) is a machine
// call that happens to block on UI, not a call that has asked the user a
// question. This is unconditional for the Security framework calls in
// passwords_app.go — a git credential helper, cron, CI, or any other
// caller of that code path always refuses the dialog rather than waiting
// behind it, because SecItemCopyMatching cannot tell this process anything
// about whether a person is watching. It is conditional for the
// /usr/bin/security calls in keychain.go: those refuse in exactly the same
// non-interactive contexts, but wait up to humanResponseTimeout instead
// when this process can tell someone is plausibly watching stderr. See
// keychain.go's isInteractive and runSecurityPrompt for that decision and
// the reasoning behind it, including the one contested case this package
// accepts as a deliberate trade-off rather than a gap: an ssh session with
// a tty on stderr but nobody at the console now waits the full
// humanResponseTimeout instead of failing at the machine bound, on the same
// asymmetry argument externalCallTimeout's floor below rests on (a bound
// that is too long costs latency on a path that was already broken; a bound
// that is too short costs a user their credential on a path that was
// working).
const maxExternalCallTimeout = 7 * time.Second

// externalCallTimeout is the default bound applied to external machine
// calls in this package.
//
// The stated policy is "2x the response time observed for that call working
// normally, capped at maxExternalCallTimeout". Applied literally to calls
// that actually succeeded — macOS 15.7.9, Intel i5-1038NG7, idle, unlocked
// 33-item login keychain, 10 samples per call; see the PR for issue #37 —
// the rule produces bounds that are *inside the noise of the measurement
// itself*:
//
//	SecItemAdd                       min 10.5ms  median 11.8ms  max 24.0ms
//	SecItemCopyMatching (hit)        min  1.5ms  median  1.7ms  max  7.0ms
//	SecItemCopyMatching (all items)  min  5.5ms  median  7.3ms  max  8.0ms
//	SecItemDelete                    min  8.9ms  median 11.3ms  max 14.4ms
//	security add-generic-password    min 36.7ms  median 40.3ms  max 46.2ms
//	security find-generic-password   min 26.7ms  median 27.3ms  max 28.1ms
//	security show-keychain-info      min 21.2ms  median 22.9ms  max 25.8ms
//	security delete-generic-password min 26.8ms  median 28.7ms  max 29.7ms
//
// 2x the median for SecItemAdd is 23.6ms, which is *below* the slowest of
// the ten samples it was derived from (24.0ms) — on an idle laptop, with
// nothing else contending. The rule as written would therefore have failed
// a healthy call roughly one run in ten before any real machine (a loaded
// CI runner, a cold securityd, a keychain with thousands of items, an
// iCloud-synced store) is considered at all.
//
// So a floor is applied. It is set at the cap minus enough margin that the
// cap stays a distinct ceiling rather than an alias for the default: 5s is
// ~108x the slowest working call observed anywhere in the table (46.2ms)
// and ~2900x the median of the operation this tool performs most often (a
// credential read). The asymmetry of the two failure modes is what settles
// the exact value: a bound that is too long costs at most a few seconds of
// latency on a path that was already broken, while a bound that is too
// short costs a user their credential on a path that was working. With the
// observed working times two orders of magnitude below anything in this
// range, there is nothing to buy by choosing 200ms over 5s, and something
// real to lose.
const externalCallTimeout = 5 * time.Second

// humanResponseTimeout bounds a wait for a *person* to answer a prompt this
// package cannot suppress — a Secret Service unlock/create dialog on Linux
// (libsecret.go's promptWaitTimeout, an alias for this constant under its
// own, call-site-specific name), or a macOS keychain-unlock or per-item
// access-control dialog (keychain.go's Keychain.promptTimeout). It is
// deliberately shared rather than reinvented per backend: the two dialogs
// are the same kind of wait — read a prompt, type a password, click Allow —
// and there is no argument on record for why a person would need more or
// less time to do that depending on which OS raised the dialog.
//
// This duration is not derived from a measurement the way
// externalCallTimeout is; there is no "normal working time" for a human to
// take 2x of. It must stay well clear of maxExternalCallTimeout on both
// sides of that judgment: it bounds a wait on a person, not a machine, so
// maxExternalCallTimeout's rationale does not apply to it at all
// (TestSecurityBoundsRespectCap and TestDbusCallTimeoutRespectsCap both
// exempt it explicitly, mirroring each other), and it must still clearly
// exceed externalCallTimeout or it would buy nothing over the machine bound
// it is meant to replace (TestHumanResponseTimeoutExceedsExternalCallTimeout,
// timeouts_test.go). humanResponseTimeoutFloor below pins the other
// direction: this value must also stay long enough to actually be useful
// for what it is meant to cover, not merely longer than the machine bound.
//
// Whether this value is applied unconditionally once a prompt-shaped call
// is reached, or only when the caller has separately decided a person is
// plausibly there to answer, is each backend's own call, not a rule this
// constant enforces: libsecret.go's promptWaitTimeout applies it
// unconditionally (see its doc comment for why — this package cannot tell
// in advance whether a Secret Service prompt is coming, so there is
// nothing to gate on), while keychain.go's Keychain.promptTimeout applies
// it only when isInteractive() finds a terminal on stderr. See
// keychain.go's isInteractive and runSecurityPrompt doc comments for that
// decision and for the one contested case it accepts as a deliberate
// trade-off rather than a gap: an ssh session with a tty on stderr but
// nobody at the console.
const humanResponseTimeout = 2 * time.Minute

// humanResponseTimeoutFloor is the minimum this package considers "enough
// time for a person to read an unfamiliar system dialog and type a
// password once". It is a judgement call, not a measurement — see
// humanResponseTimeout's own doc comment for why there is no "normal
// working time" to derive a floor from the way externalCallTimeout's floor
// was derived from measured working-call latency.
//
// 30 seconds is chosen because it comfortably covers the two components of
// that task that can be estimated at all even without a measurement:
// reading a short, unfamiliar dialog (on the order of 5-10s for someone who
// has never seen it before) and locating and typing a password, by hand or
// via a password manager, including one mistyped attempt (on the order of
// another 10-20s). Existing without being enforced, this claim is not
// worth much: TestHumanResponseTimeoutMeetsFloor (timeouts_test.go) is what
// stops humanResponseTimeout drifting below it while still passing
// TestHumanResponseTimeoutExceedsExternalCallTimeout — a value like 6
// seconds would satisfy "longer than the 5-second machine bound" while
// being useless for the person it is named after, which is exactly the
// #67 complaint again at a different number.
const humanResponseTimeoutFloor = 30 * time.Second
