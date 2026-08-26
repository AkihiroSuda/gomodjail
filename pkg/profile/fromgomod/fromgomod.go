package fromgomod

import (
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/AkihiroSuda/gomoddirectivecomments"
	"golang.org/x/mod/modfile"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
)

// ParseFile reads the go.mod at path and builds its gomodjail profile. The
// returned modfile.File keeps the comment syntax tree, so callers can inspect
// require lines or edit annotations (pkg/profile/gomodedit) and re-format it.
func ParseFile(path string) (*modfile.File, *profile.Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(path, b)
}

// Parse is ParseFile for already-read go.mod contents, for callers that need
// the raw bytes as well (e.g. to detect concurrent go.mod edits later); path
// is used in error messages only.
func Parse(path string, b []byte) (*modfile.File, *profile.Profile, error) {
	mf, err := modfile.Parse(path, b, nil)
	if err != nil {
		return nil, nil, err
	}
	if mf.Module == nil {
		// modfile.Parse accepts a go.mod without a module directive, but
		// FromGoMod would dereference it.
		return nil, nil, fmt.Errorf("go.mod %q has no module directive", path)
	}
	prof := profile.New()
	if err := FromGoMod(mf, prof); err != nil {
		return nil, nil, fmt.Errorf("failed to read profile from %q: %w", path, err)
	}
	return mf, prof, nil
}

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
