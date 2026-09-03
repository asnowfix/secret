// Command git-credential-secret implements git's credential-helper protocol
// (see gitcredentials(7) and git-credential(1)) on top of the same
// platform-native secret store the `secret` CLI uses.
//
// It is its own binary rather than a `secret` subcommand because
// `credential.helper` is a git config *value*, not a subcommand-with-args
// pattern one gets to invent: a bare value like `credential.helper = secret`
// makes git run `git credential-secret <op>`, which resolves through git's
// ordinary subcommand-on-PATH lookup to an executable literally named
// `git-credential-secret`. There is no configuration form where git invokes
// `<binary> <subcommand>` as a single configured helper (confirmed locally
// against gitcredentials(7) and git-credential(1); see the implementing PR's
// description for the full trail). So this has to be reachable as
// `git-credential-secret` on PATH for `git config credential.helper secret`
// to work — hence a dedicated build target/binary rather than, say, a
// symlink or wrapper script users would have to create by hand (fragile on
// Windows in particular, where symlinks need Developer Mode or admin
// rights).
//
// Keeping this outside the `secret` Cobra command tree entirely is also the
// security boundary for the protocol's `get` operation, which necessarily
// writes a plaintext password to stdout: that behaviour is reachable only
// through this one intentional entry point, never through a mistyped
// ordinary `secret` subcommand. See cmd/gitcredential.go for the protocol
// implementation itself, shared with (but not exposed by) the `secret`
// binary.
package main

import (
	"fmt"
	"os"

	"github.com/asnowfix/secret/cmd"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: git-credential-secret <get|store|erase>")
		os.Exit(1)
	}
	os.Exit(cmd.RunGitCredentialHelper(os.Args[1], os.Stdin, os.Stdout, os.Stderr))
}
