package run

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/child"
	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/env"
	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/parent"
	"github.com/AkihiroSuda/gomodjail/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/pkg/profile/fromgomod"
	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
)

func Example() string {
	return "TBD"
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "run COMMAND...",
		Short:                 "Run a Go program with confinement",
		Example:               Example(),
		Args:                  cobra.MinimumNArgs(1),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("go-mod", "", "go.mod file with comment lines like `gomodjail:confined`")
	flags.StringToString("policy", nil, "e.g., example.com/module=confined")
	flags.Bool("no-policy", false, "Allow running without any policy (useful only for debugging)")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	if _, ok := os.LookupEnv(env.PrivateChild); ok {
		return child.Main(args)
	}
	prof := profile.New()
	flagGoMod, err := flags.GetString("go-mod")
	if err != nil {
		return err
	}
	if flagGoMod != "" {
		goModB, err := os.ReadFile(flagGoMod)
		if err != nil {
			return err
		}
		goModFile, err := modfile.Parse(flagGoMod, goModB, nil)
		if err != nil {
			return err
		}
		if err = fromgomod.FromGoMod(goModFile, prof); err != nil {
			return fmt.Errorf("failed to read profile from %q: %w", flagGoMod, err)
		}
	}
	flagPolicy, err := flags.GetStringToString("policy")
	if err != nil {
		return err
	}
	for k, v := range flagPolicy {
		if oldV, ok := prof.Modules[k]; ok && oldV != v {
			slog.Warn("Overwriting policy", "module", k, "old", oldV, "new", v)
		}
		prof.Modules[k] = v
	}
	flagNoPolicy, err := flags.GetBool("no-policy")
	if err != nil {
		return err
	}
	if !flagNoPolicy && len(prof.Modules) == 0 {
		return errors.New("no policy was specified (Hint: specify --go-mod=FILE, or --policy=MODULE=POLICY)")
	}
	if err = prof.Validate(); err != nil {
		return err
	}
	return parent.Main(prof, args)
}
