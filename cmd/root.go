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
		if cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "version" {
			return nil
		}
		var err error
		b, err = selectBackend()
		if err != nil {
			return err
		}
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

// selectBackend is implemented per-platform in backend_*.go files. Each
// implementation reads the SECRET_BACKEND environment variable via
// viper.GetString("backend") (Viper's SetEnvPrefix+AutomaticEnv above maps
// that key to the SECRET_BACKEND env var) to override the platform default
// at runtime — see issue #7. It returns an error for a SECRET_BACKEND value
// it does not recognise on the current platform rather than silently
// falling back to the default.
