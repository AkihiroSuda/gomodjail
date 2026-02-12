package fromgomod

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/AkihiroSuda/gomoddirectivecomments"
	"golang.org/x/mod/modfile"

	"github.com/AkihiroSuda/gomodjail/pkg/profile"
)

func FromGoMod(mod *modfile.File, prof *profile.Profile) error {
	prof.Module = mod.Module.Mod.Path
	var err error
	parsedPolicies, err := gomoddirectivecomments.Parse(mod, "gomodjail", profile.PolicyUnconfined)
	if err != nil {
		return fmt.Errorf("failed to parse Go module directive comments: %w", err)
	}
	for modPath, pol := range parsedPolicies {
		if !slices.Contains(profile.KnownPolicies, pol) {
			return fmt.Errorf("module %q: unknown policy %q", modPath, pol)
		}
		if existPol, ok := prof.Modules[modPath]; ok && existPol != pol {
			slog.Warn("Overwriting an existing policy", "module", modPath, "old", existPol, "new", pol)
		}
	}
	prof.Modules = parsedPolicies
	return nil
}
