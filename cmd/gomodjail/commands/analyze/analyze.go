package analyze

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/AkihiroSuda/gosocialcheck/cmd/gosocialcheck/flagutil"
	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/AkihiroSuda/gomodjail/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/pkg/profile/fromgomod"
	"github.com/AkihiroSuda/gomodjail/pkg/staticanalysis/analyzer"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "analyze [flags] [packages]",
		Short:                 "Run static analyzer",
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("target-mode", "depender", "Target mode: depender or dependee")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()
	targetPkgs := args
	targetMode, err := flags.GetString("target-mode")
	if err != nil {
		return err
	}
	switch targetMode {
	case "depender":
		if len(args) != 1 || args[0] != "./..." {
			return fmt.Errorf("depender mode currently expects the argument to be \"./...\"")
		}
		goMod := filepath.Join(".", "go.mod")
		targetMods, err := dependerModeConfinedModules(ctx, goMod)
		if err != nil {
			return err
		}
		targetPkgs = stringSliceAppendSuffix(targetMods, "/...")
		slog.DebugContext(ctx, "depender mode: analyzing confined dependencies", "targets", targetMods)
	case "dependee":
		// NOP
	default:
		return fmt.Errorf("invalid target mode: %q", targetMode)
	}

	// Rewrite the global os.Args, as a workaround for:
	// - https://github.com/AkihiroSuda/gosocialcheck/issues/1
	// - https://github.com/golang/go/issues/73875
	//
	// golang.org/x/tools/go/analysis/singlechecker parses the global args
	// rather than flag.FlagSet.Args, and raises an error:
	// `-: package run is not in std (/opt/homebrew/Cellar/go/1.24.3/libexec/src/run`
	os.Args = append([]string{"gomodjail-analyze", "-test=false"}, targetPkgs...)
	goflags := flagutil.PFlagSetToGoFlagSet(flags, []string{"debug", "target-mode"})
	if err := goflags.Parse(args); err != nil {
		return err
	}
	opts := analyzer.Opts{
		Flags: *goflags,
	}
	a, err := analyzer.New(ctx, opts)
	if err != nil {
		return err
	}
	singlechecker.Main(a)
	// NOTREACHED
	return nil
}

func dependerModeConfinedModules(ctx context.Context, goMod string) ([]string, error) {
	prof := profile.New()
	goModB, err := os.ReadFile(goMod)
	if err != nil {
		return nil, err
	}
	goModFile, err := modfile.Parse(goMod, goModB, nil)
	if err != nil {
		return nil, err
	}
	if err = fromgomod.FromGoMod(goModFile, prof); err != nil {
		return nil, fmt.Errorf("failed to read profile from %q: %w", goMod, err)
	}
	if len(prof.Modules) == 0 {
		return nil, fmt.Errorf("no policy was specified in %q", goMod)
	}
	if err = prof.Validate(); err != nil {
		return nil, err
	}
	var confined []string
	for mod, pol := range prof.Modules {
		if pol != profile.PolicyUnconfined {
			confined = append(confined, mod)
		}
	}
	return confined, nil
}

func stringSliceAppendSuffix(slice []string, suffix string) []string {
	res := make([]string, len(slice))
	for i, s := range slice {
		res[i] = s + suffix
	}
	return res
}
