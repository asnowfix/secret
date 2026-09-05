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
		if err := runList(); err != nil {
			fmt.Fprintf(os.Stderr, "*** %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

// runList prints one service name per line to stdout and returns the
// backend's error, if any. Split out from RunE so the error path can be
// exercised by a test without going through RunE's os.Exit(1).
func runList() error {
	services, err := b.List()
	if err != nil {
		return err
	}
	for _, service := range services {
		fmt.Println(service)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(listCmd)
}
