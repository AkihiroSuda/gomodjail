package main

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/AkihiroSuda/gomodjail/cmd/gomodjail/commands/pack"
	"github.com/AkihiroSuda/gomodjail/cmd/gomodjail/commands/run"
	"github.com/AkihiroSuda/gomodjail/cmd/gomodjail/version"
	"github.com/AkihiroSuda/gomodjail/pkg/cache"
	"github.com/AkihiroSuda/gomodjail/pkg/env"
	"github.com/AkihiroSuda/gomodjail/pkg/envutil"
	"github.com/AkihiroSuda/gomodjail/pkg/osargs"
	"github.com/AkihiroSuda/gomodjail/pkg/tracer"
	"github.com/AkihiroSuda/gomodjail/pkg/ziputil"
	"github.com/spf13/cobra"
)

var logLevel = new(slog.LevelVar)

func main() {
	if exitCode := xmain(); exitCode != 0 {
		os.Exit(exitCode)
	}
}

func xmain() int {
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	rootCmd := newRootCommand()
	if _, ok := os.LookupEnv(env.PrivateChild); !ok {
		zr, err := ziputil.FindSelfExtractArchive()
		if err != nil {
			slog.Error("error while detecting self-extract archive", "error", err)
		}
		if zr != nil {
			err := configureSelfExtractMode(rootCmd, zr)
			if cErr := zr.Close(); cErr != nil {
				slog.Error("failed to call closer", "error", cErr)
			}
			if err != nil {
				slog.Error("exiting with an error while setting up self-extract mode", "error", err)
				return 1
			}
		}
	}
	err := rootCmd.Execute()
	if err != nil {
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			if ps := exitErr.ProcessState; ps != nil {
				exitCode = ps.ExitCode()
			}
		} else if exitErr, ok := err.(*tracer.ExitError); ok {
			exitCode = exitErr.ExitCode
		}
		if exitCode != 0 {
			slog.Debug("exiting with an error", "error", err, "exitCode", exitCode)
		} else {
			slog.Debug("exiting")
		}
		return exitCode
	}
	return 0
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
				_ = os.Setenv("DEBUG", "1")
			}
		}
		return nil
	}

	cmd.AddCommand(
		run.New(),
		pack.New(),
	)
	return cmd
}

func configureSelfExtractMode(rootCmd *cobra.Command, zr *zip.ReadCloser) error {
	slog.Debug("Running in self-extract mode")

	// td must be kept on exit
	// https://github.com/containerd/nerdctl/pull/4012#issuecomment-2840539282
	td, err := cache.ExecutableDir()
	if err != nil {
		return err
	}
	slog.Debug("unpacking self-extract archive", "dir", td)
	fis, err := ziputil.Unzip(td, zr)
	if err != nil {
		return fmt.Errorf("failed to unzip to %q: %w", td, err)
	}
	var libgomodjailHookFI, progFI, goModFI fs.FileInfo
	switch runtime.GOOS {
	case "darwin":
		if len(fis) != 3 {
			return fmt.Errorf("expected an archive to contain 3 files (libgomodjail_hook_darwin.dylib, program and go.mod), got %d files", len(fis))
		}
		libgomodjailHookFI, progFI, goModFI = fis[0], fis[1], fis[2]
	default:
		if len(fis) != 2 {
			return fmt.Errorf("expected an archive to contain 2 files (program and go.mod), got %d files", len(fis))
		}
		progFI, goModFI = fis[0], fis[1]
	}
	if filepath.Base(progFI.Name()) != progFI.Name() {
		return fmt.Errorf("unexpected file name: %q", progFI.Name())
	}
	if goModFI.Name() != "go.mod" {
		return fmt.Errorf("expected \"go.mod\", got %q", goModFI.Name())
	}
	prog := filepath.Join(td, progFI.Name())
	goMod := filepath.Join(td, goModFI.Name())
	switch runtime.GOOS {
	case "darwin":
		if libgomodjailHookFI.Name() != "libgomodjail_hook_darwin.dylib" {
			return fmt.Errorf("expected \"libgomodjail_hook_darwin.dylib\", got %q", libgomodjailHookFI.Name())
		}
		libgomodjailHook := filepath.Join(td, libgomodjailHookFI.Name())
		if err = os.Setenv("LIBGOMODJAIL_HOOK", libgomodjailHook); err != nil {
			return err
		}
	}
	args := append([]string{os.Args[0], "run", "--go-mod=" + goMod, prog, "--"}, os.Args[1:]...)
	slog.Debug("Reconfiguring the top-level command", "args", args)
	rootCmd.SetArgs(args[1:])
	osargs.SetOSArgs(args)
	return nil
}
