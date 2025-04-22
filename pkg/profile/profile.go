package profile

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

type Policy = string

const (
	PolicyUnconfined = "unconfined"
	PolicyConfined   = "confined"
)

var KnownPolicies = []Policy{
	PolicyUnconfined,
	PolicyConfined,
}

func New() *Profile {
	return &Profile{
		Modules: make(map[string]Policy),
	}
}

type Profile struct {
	Module  string            // the "module" line of go.mod
	Modules map[string]Policy // the "require" lines of go.mod TODO: rename to "Requires"? "Dependencies"?
}

func (p *Profile) Validate() error {
	if p.Module == "" {
		return errors.New("no module was specified")
	}
	if len(p.Modules) == 0 {
		slog.Warn("No policy was specified")
	}

	for k, v := range p.Modules {
		if !slices.Contains(KnownPolicies, v) {
			return fmt.Errorf("unknown policy %q was specified for module %q", v, k)
		}
	}
	return nil
}

type Confinment struct {
	Module string
	Policy Policy
}

func (p *Profile) Confined(mainMod, sym string) *Confinment {
	if mainMod != p.Module {
		slog.Warn("module mismatch", "a", mainMod, "b", p.Module)
		return nil
	}
	for module, policy := range p.Modules {
		switch policy {
		case PolicyConfined:
			if sym == module || strings.HasPrefix(sym, module+"/") || strings.HasPrefix(sym, module+".") {
				return &Confinment{
					Module: module,
					Policy: policy,
				}
			}
		}
	}
	return nil
}
