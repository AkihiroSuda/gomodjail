package pack

import (
	"archive/zip"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AkihiroSuda/gomodjail/pkg/tracer"
	"github.com/AkihiroSuda/gomodjail/pkg/ziputil"
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
	flags.StringP("output", "o", "", "output file (default: <FILE>.gomodjail)")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	flagGoMod, err := flags.GetString("go-mod")
	if err != nil {
		return err
	}
	if flagGoMod == "" {
		return errors.New("needs --go-mod")
	}
	prog := args[0]
	flagOutput, err := flags.GetString("output")
	if err != nil {
		return err
	}
	if flagOutput == "" {
		flagOutput = filepath.Base(prog) + ".gomodjail"
	}

	slog.Info("Creating a self-extract archive", "file", flagOutput)
	out, err := os.OpenFile(flagOutput, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck

	selfExe, err := os.Executable()
	if err != nil {
		return err
	}
	selfExeF, err := os.Open(selfExe)
	if err != nil {
		return err
	}
	defer selfExeF.Close() //nolint:errcheck
	if _, err := io.Copy(out, selfExeF); err != nil {
		return err
	}

	zw := zip.NewWriter(out)
	defer zw.Close() //nolint:errcheck
	if runtime.GOOS == "darwin" {
		libgomodjailHook, err := tracer.LibgomodjailHook()
		if err != nil {
			return err
		}
		if err := ziputil.WriteFileWithPath(zw, libgomodjailHook, "libgomodjail_hook_darwin.dylib"); err != nil {
			return err
		}
	}
	if err := ziputil.WriteFileWithPath(zw, prog, filepath.Base(prog)); err != nil {
		return err
	}
	if err := ziputil.WriteFileWithPath(zw, flagGoMod, "go.mod"); err != nil {
		return err
	}
	if err := zw.SetComment(ziputil.SelfExtractArchiveComment); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	return out.Close()
}
