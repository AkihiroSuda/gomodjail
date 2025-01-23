package main

import (
	"log/slog"
	"os"
	"os/exec"

	"github.com/AkihiroSuda/gomodjail/cmd/gomodjail/commands/run"
	"github.com/AkihiroSuda/gomodjail/cmd/gomodjail/version"
	"github.com/AkihiroSuda/gomodjail/pkg/envutil"
	"github.com/spf13/cobra"
)

var logLevel = new(slog.LevelVar)

func main() {
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	if err := newRootCommand().Execute(); err != nil {
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ps := exitErr.ProcessState; ps != nil {
				exitCode = ps.ExitCode()
			}
		}
		slog.Error("exiting with an error", "error", err)
		os.Exit(exitCode)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "gomodjail",
		Short:         "Jail for go modules",
		Example:       run.Example(),
		Version:       version.GetVersion(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := cmd.PersistentFlags()
	flags.Bool("debug", envutil.Bool("DEBUG", false), "debug mode [$DEBUG]")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			logLevel.Set(slog.LevelDebug)
			if _, ok := os.LookupEnv("DEBUG"); !ok {
				// Parsed by libgomodjail_hook_darwin
				os.Setenv("DEBUG", "1")
			}
		}
		return nil
	}

	cmd.AddCommand(
		run.New(),
	)
	return cmd
}
