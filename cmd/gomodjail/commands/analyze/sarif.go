package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

// SARIF 2.1.0 output for code-scanning integrations (GitHub, etc.).
//
// Witness call paths run through the module cache, not the analyzed
// repository, so a finding cannot be anchored to the frame that earns the
// capability. Instead each result points at the confined module's require
// line in go.mod: that is the reviewable location — the line whose
// `// gomodjail:confined` annotation the finding is a verdict on.
//
// Rule vocabulary: one rule per capability class (EXEC, FILES/READ, ...), so
// code-scanning UIs group findings the way the policy reasons about them.
// Violations are level "error"; caveats are "warning" ("error" under
// --strict, matching the exit-code contract).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func reportSARIF(w io.Writer, reports []policy.ModuleReport, src *profileSource, strict bool) error {
	caveatLevel := "warning"
	if strict {
		caveatLevel = "error"
	}

	var results []sarifResult
	rules := make(map[string]sarifRule)
	addRule := func(capability, tier string) {
		if _, ok := rules[capability]; !ok {
			rules[capability] = sarifRule{
				ID: capability,
				ShortDescription: sarifMessage{
					Text: fmt.Sprintf("A confined module reaches the %s capability (%s tier)", capability, tier),
				},
			}
		}
	}
	for _, r := range reports {
		for _, v := range r.Violations {
			addRule(v.Capability, "deny")
			results = append(results, sarifResult{
				RuleID: v.Capability,
				Level:  "error",
				Message: sarifMessage{Text: fmt.Sprintf("confined module %s reaches %s: %s",
					r.Module, v.Capability, witnessText(v))},
				Locations: moduleLocation(src, r.Module),
			})
		}
		for _, c := range r.Caveats {
			addRule(c.Capability, "caveat")
			results = append(results, sarifResult{
				RuleID: c.Capability,
				Level:  caveatLevel,
				Message: sarifMessage{Text: fmt.Sprintf("confined module %s uses %s, which cannot be statically verified: %s",
					r.Module, c.Capability, witnessText(c))},
				Locations: moduleLocation(src, r.Module),
			})
		}
	}

	sortedRules := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		sortedRules = append(sortedRules, rule)
	}
	sort.Slice(sortedRules, func(i, j int) bool { return sortedRules[i].ID < sortedRules[j].ID })

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "gomodjail",
				InformationURI: "https://github.com/AkihiroSuda/gomodjail",
				Rules:          sortedRules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// witnessText renders a witness call path on one line, root first.
func witnessText(wit policy.Witness) string {
	frames := make([]string, 0, len(wit.Path))
	for _, fr := range wit.Path {
		name := fr.Name
		if name == "" {
			name = fr.Package
		}
		frames = append(frames, name)
	}
	if len(frames) == 0 {
		return "(no witness path)"
	}
	return strings.Join(frames, " -> ")
}

// moduleLocation anchors a finding to the module's require line in go.mod.
// Without a go.mod (--policy-only invocations) the result carries no
// location, which SARIF permits.
func moduleLocation(src *profileSource, module string) []sarifLocation {
	if src == nil || src.GoMod == "" {
		return nil
	}
	loc := sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: src.GoMod}}
	if line, ok := src.ModuleLine[module]; ok {
		loc.Region = &sarifRegion{StartLine: line}
	}
	return []sarifLocation{{PhysicalLocation: loc}}
}
