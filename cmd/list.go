package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the service names of all secrets in the backend",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		services, err := b.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		for _, service := range services {
			fmt.Println(service)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
