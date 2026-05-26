package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add <service> [<account>] <password>",
	Short: "Store a credential in the secret store",
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

		if err := b.Add(service, account, password); err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "stored '%s' (account: %s) with non-interactive ACL\n", service, account)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
