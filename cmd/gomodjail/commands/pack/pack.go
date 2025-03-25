package pack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AkihiroSuda/gomodjail/pkg/cp"
	"github.com/spf13/cobra"
)

func Example() string {
	return `  # Pack nerdctl with gomodjail
  gomodjail pack --go-mod=go.mod /usr/local/bin/nerdctl
`
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "pack FILE",
		Short:                 "Pack a Go program with gomodjail",
		Example:               Example(),
		Args:                  cobra.ExactArgs(1),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("go-mod", "", "go.mod file with comment lines like `gomodjail:confined`")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()
	flagGoMod, err := flags.GetString("go-mod")
	if err != nil {
		return err
	}
	if flagGoMod == "" {
		return errors.New("needs --go-mod")
	}
	prog := args[0]
	progBase := filepath.Base(prog)
	progAbs, err := filepath.Abs(prog)
	if err != nil {
		return err
	}

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}

	makeself, err := exec.LookPath("makeself")
	if err != nil {
		return fmt.Errorf("%w (Hint: apt/dnf/brew install makeself)", err)
	}

	td, err := os.MkdirTemp("", "gomodjail-pack-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(td) //nolint:errcheck

	files := map[string]string{
		"gomodjail": selfExe,
		"go.mod":    flagGoMod,
		progBase:    progAbs,
	}
	for dstBase, src := range files {
		dst := filepath.Join(td, dstBase)
		if err = cp.CopyFile(dst, src, 0o500); err != nil {
			return fmt.Errorf("failed to copy %q to %q: %w", src, dst, err)
		}
	}

	oldWD, err := os.Getwd()
	if err != nil {
		return err
	}

	makeselfCmd := exec.CommandContext(ctx, makeself,
		"--nomd5",
		"--nocrc",
		"--nocomp",
		"--noprogress",
		"--quiet",
		"--packaging-date", "Thu Jan  1 09:00:00 AM JST 1970",
		// TODO: make targetdir deterministic
		".",
		progBase+".gomodjail",
		progBase+" with gomodjail",
		"./gomodjail",
		"run",
		"--go-mod=go.mod",
		"--",
		progBase,
	)
	makeselfCmd.Dir = td
	makeselfCmd.Stdout = cmd.OutOrStdout()
	makeselfCmd.Stderr = cmd.ErrOrStderr()
	slog.InfoContext(ctx, "Running makeself", "cmd", makeselfCmd.Args)
	if err = makeselfCmd.Run(); err != nil {
		return err
	}

	src := filepath.Join(td, progBase+".gomodjail")
	dst := filepath.Join(oldWD, progBase+".gomodjail")
	if err = cp.CopyFile(dst, src, 0o500); err != nil {
		return fmt.Errorf("failed to copy %q to %q: %w", src, dst, err)
	}
	return patchMakeselfHeader(ctx, dst)
}

func patchMakeselfHeader(ctx context.Context, f string) error {
	cmd := exec.CommandContext(ctx, "sed", "-i", `s/^quiet="n"/quiet="y"/`, f)
	slog.InfoContext(ctx, "Patching makeself header", "cmd", cmd.Args)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%q)", err, string(out))
	}
	return nil
}
