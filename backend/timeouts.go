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
// type a password reasonably needs longer. promptWaitTimeout in
// libsecret.go (2 minutes, for a Secret Service unlock prompt) is the one
// deliberate wait-for-a-human in this package and is excluded on that
// ground.
//
// A GUI dialog on the machine side does not make a call a wait-for-a-human:
// an unbounded SecItemCopyMatching behind a keychain-unlock or ACL
// authorization dialog (issue #37, #44) is a machine call that happens to
// block on UI. Nothing has asked the user a question they can answer in the
// non-interactive contexts this tool runs in — git credential helper, cron,
// CI, ssh — so those calls are in scope and are made to refuse the dialog
// rather than wait behind it (see passwords_app.go).
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
