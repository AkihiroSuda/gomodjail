package fromgomod

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/AkihiroSuda/gomodjail/pkg/profile"
)

func FromGoMod(mod *modfile.File, prof *profile.Profile) error {
	prof.Module = mod.Module.Mod.Path
	currentDefaultPolicy := profile.PolicyUnconfined

	for _, c := range append(mod.Module.Syntax.Before, mod.Module.Syntax.Suffix...) {
		if tok := c.Token; tok != "" {
			pol, err := policyFromComment(tok)
			if err != nil {
				err = fmt.Errorf("failed to parse comment %+v: %w", c, err)
				return err
			}
			currentDefaultPolicy = pol
		}
	}

	for _, c := range append(mod.Go.Syntax.Before, mod.Go.Syntax.Suffix...) {
		if tok := c.Token; tok != "" {
			pol, err := policyFromComment(tok)
			if err != nil {
				err = fmt.Errorf("failed to parse comment %+v: %w", c, err)
				return err
			}
			return fmt.Errorf("policy %q is specified in an invalid position", pol)
		}
	}

	for _, f := range mod.Require {
		if syn := f.Syntax; syn != nil {
			pol := currentDefaultPolicy
			for _, c := range append(syn.Before, syn.Suffix...) {
				if tok := c.Token; tok != "" {
					polFromComment, err := policyFromComment(tok)
					if err != nil {
						err = fmt.Errorf("failed to parse comment %+v: %w", c, err)
						return err
					}
					if polFromComment != "" {
						pol = polFromComment
					}
				}
			}
			if pol == "" {
				pol = currentDefaultPolicy
			}
			if pol == profile.PolicyUnconfined {
				pol = "" // reduce map size
			}
			if existPol, ok := prof.Modules[f.Mod.Path]; ok && existPol != pol {
				slog.Warn("Overwriting an existing policy", "module", f.Mod.Path, "old", existPol, "new", pol)
			}
			if pol == "" {
				delete(prof.Modules, f.Mod.Path)
			} else {
				prof.Modules[f.Mod.Path] = pol
			}
		}
	}
	return nil
}

func policyFromComment(token string) (string, error) {
	token = strings.TrimPrefix(token, "//")
	// TODO: support /* ... */
	for _, f := range strings.Fields(token) {
		f = strings.TrimPrefix(f, "//")
		if strings.HasPrefix(f, "gomodjail:") {
			pol := profile.Policy(strings.TrimPrefix(f, "gomodjail:"))
			if !slices.Contains(profile.KnownPolicies, pol) {
				return pol, fmt.Errorf("unknown policy %q", pol)
			}
			return pol, nil
		}
	}
	return "", nil
}
