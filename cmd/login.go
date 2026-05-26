package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:     "login <service>",
	Aliases: []string{"username", "client_id"},
	Short:   "Retrieve the account/username for a service",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		username, err := b.GetUsername(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		fmt.Print(username)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
