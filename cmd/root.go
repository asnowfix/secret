package cmd

import (
	"os"

	"github.com/asnowfix/secret/backend"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var b backend.Backend

var rootCmd = &cobra.Command{
	Use:   "secret",
	Short: "CLI for desktop secret managers",
	Long:  "A unified CLI that delegates to the platform's native secret store.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "help" || cmd.Name() == "completion" {
			return nil
		}
		b = selectBackend()
		if err := b.IsAvailable(); err != nil {
			return err
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	viper.SetEnvPrefix("SECRET")
	viper.AutomaticEnv()
}

// selectBackend is implemented per-platform in backend_*.go files.
// TODO: Support backend selection via config/env (SECRET_BACKEND).
// TODO: Add KeePassXC backend (macOS, Windows, Linux) — cross-platform.
