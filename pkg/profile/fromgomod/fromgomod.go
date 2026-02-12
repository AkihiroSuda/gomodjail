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
			if syn.InBlock {
				// TODO: cache line blocks
				if lineBlock := findLineBlock(mod.Syntax.Stmt, syn); lineBlock != nil {
					lineBlockPol, err := policyFromLineBlock(lineBlock)
					if err != nil {
						err = fmt.Errorf("failed to parse line block %+v: %w", lineBlock, err)
						return err
					}
					if lineBlockPol != "" {
						pol = lineBlockPol
					}
				}
			}
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

func findLineBlock(exprs []modfile.Expr, line modfile.Expr) *modfile.LineBlock {
	start, end := line.Span()
	for _, expr := range exprs {
		lb, ok := expr.(*modfile.LineBlock)
		if !ok {
			continue
		}
		lbStart, lbEnd := lb.Span()
		if start.Line >= lbStart.Line && end.Line <= lbEnd.Line {
			return lb
		}
	}
	return nil
}

func policyFromLineBlock(lb *modfile.LineBlock) (string, error) {
	for _, c := range append(lb.Before, lb.Suffix...) {
		if tok := c.Token; tok != "" {
			pol, err := policyFromComment(tok)
			if err != nil {
				return "", err
			}
			if pol != "" {
				return pol, nil
			}
		}
	}
	return "", nil
}
