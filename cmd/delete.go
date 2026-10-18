package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/asnowfix/secret/backend"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <service>",
	Short: "Remove a credential from the secret store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := deleteCredential(b, args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}

// deleteCredential removes the credential for service. When the backend
// refuses with *backend.ErrAmbiguous (more than one item matches, #49) it
// deleted nothing, and the error says so and how to resolve it by hand: this
// command cannot choose between the items, so the user removes the extra one
// in the native tool.
func deleteCredential(be backend.Backend, service string) error {
	err := be.Delete(service)
	var ambiguous *backend.ErrAmbiguous
	if errors.As(err, &ambiguous) {
		return fmt.Errorf("%w; nothing was deleted: %s", err, ambiguousRemedy(service))
	}
	return err
}
