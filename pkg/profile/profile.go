package profile

import (
	"fmt"
	"log/slog"
	"slices"
)

type Policy = string

const (
	PolicyConfined = "confined"
)

var KnownPolicies = []Policy{
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
