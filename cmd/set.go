package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/asnowfix/secret/backend"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set <service> [<account>] <password>",
	Short: "Store a credential in the secret store (overwrites if exists)",
	Args:  cobra.RangeArgs(2, 3),
	RunE: func(cmd *cobra.Command, args []string) error {
		var service, account, password string
		service = args[0]
		if len(args) == 3 {
			account = args[1]
			password = args[2]
		} else {
			account = args[0]
			password = args[1]
		}

		_, err := b.GetPassword(service)
		exists, indeterminate := classifySetTarget(err)
		if indeterminate != nil {
			return fmt.Errorf("could not determine whether a credential for '%s' already exists, refusing to risk an unconfirmed overwrite: %w", service, indeterminate)
		}
		if exists {
			yes, _ := cmd.Flags().GetBool("yes")
			if !yes {
				fmt.Fprintf(os.Stderr, "credential for '%s' already exists. Overwrite? [y/N] ", service)
				reader := bufio.NewReader(os.Stdin)
				answer, _ := reader.ReadString('\n')
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer != "y" && answer != "yes" {
					fmt.Fprintln(os.Stderr, "aborted")
					return nil
				}
			}
			if err := b.Delete(service); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not remove old credential: %v\n", err)
			}
		}

		if err := b.Add(service, account, password); err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "stored '%s' (account: %s) with non-interactive ACL\n", service, account)
		return nil
	},
}

func init() {
	setCmd.Flags().BoolP("yes", "y", false, "Skip confirmation when overwriting")
	rootCmd.AddCommand(setCmd)
}

// classifySetTarget interprets the error returned by GetPassword(service)
// into whether the credential should be treated as already existing.
//
// This is shared by every backend (macOS Keychain/Passwords.app, Windows
// Credential Manager, Linux Secret Service), so it does not merely check
// err == nil: on the Linux backend, a GetPassword call can fail for reasons
// that have nothing to do with the credential's existence — a re-locked
// keyring, a stale D-Bus session, a transport fault — while the credential
// in fact still exists. Treating any non-nil error as "doesn't exist" would
// skip the overwrite confirmation below and let Add's replace-on-write
// silently clobber it (see PR #29's review, CRITICAL 1: "secret set can
// silently destroy an existing credential"). Only a definitive
// *backend.ErrNotFound counts as "does not exist"; anything else is
// reported back as indeterminate rather than guessed at.
func classifySetTarget(err error) (exists bool, indeterminate error) {
	if err == nil {
		return true, nil
	}
	var notFound *backend.ErrNotFound
	if errors.As(err, &notFound) {
		return false, nil
	}
	return false, err
}
