package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var passwordCmd = &cobra.Command{
	Use:     "password <service>",
	Aliases: []string{"client_secret"},
	Short:   "Retrieve the password for a service",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := b.GetPassword(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		fmt.Print(password)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(passwordCmd)
}
