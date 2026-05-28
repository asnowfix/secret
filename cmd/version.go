package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Injected at build time via -ldflags "-X github.com/asnowfix/secret/cmd.version=<tag>"
var version string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the build version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(resolveVersion())
	},
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				rev = s.Value[:7]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if dirty {
		return "g" + rev + "-dirty"
	}
	return "g" + rev
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
