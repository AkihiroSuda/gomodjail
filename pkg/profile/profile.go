package profile

import (
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
	Modules map[string]Policy
}

func (p *Profile) Validate() error {
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

func (p *Profile) Confined(sym string) *Confinment {
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
