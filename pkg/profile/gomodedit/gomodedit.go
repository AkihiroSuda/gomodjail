// Package gomodedit is the write-side counterpart of pkg/profile/fromgomod:
// it rewrites gomodjail policy annotations ("// gomodjail:confined") on the
// require lines of a parsed go.mod. Only the targeted annotation field is
// touched; all other comment text, and the annotation grammar recognized by
// github.com/AkihiroSuda/gomoddirectivecomments, is preserved.
package gomodedit

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/mod/modfile"
)

// namespace is the directive-comment namespace, as in "// gomodjail:confined".
const namespace = "gomodjail"

// SetPolicy sets the gomodjail policy annotation for the given module on its
// require line(s) in mf. An existing per-line annotation is rewritten in
// place; otherwise the annotation is added as a per-line comment — appended
// to the suffix comment, or, for `// indirect` requires, on its own line
// above (the suffix stays exactly `// indirect` for other toolchains) — so
// that it overrides any block- or file-level default. It reports whether the
// file changed, and errors if the module has no require line. The caller
// renders the result with modfile.Format.
func SetPolicy(mf *modfile.File, module, policy string) (bool, error) {
	found := false
	changed := false
	for _, req := range mf.Require {
		if req.Mod.Path != module || req.Syntax == nil {
			continue
		}
		found = true
		if setPolicyOnLine(req.Syntax, policy, req.Indirect) {
			changed = true
		}
	}
	if !found {
		return false, fmt.Errorf("module %q has no require line", module)
	}
	return changed, nil
}

func setPolicyOnLine(line *modfile.Line, policy string, indirect bool) bool {
	annotation := namespace + ":" + policy
	rewrote := false
	changed := false
	rewrite := func(comments []modfile.Comment) {
		for i := range comments {
			tok, ok := rewriteToken(comments[i].Token, annotation)
			if !ok {
				continue
			}
			rewrote = true
			if tok != comments[i].Token {
				comments[i].Token = tok
				changed = true
			}
		}
	}
	// The parser reads Before then Suffix, later annotations winning, so
	// every occurrence must be rewritten for the line to mean `policy`.
	rewrite(line.Before)
	rewrite(line.Suffix)
	if rewrote {
		return changed
	}
	switch n := len(line.Suffix); {
	case indirect:
		// The go command and other toolchains parse the `// indirect` suffix;
		// keep it byte-for-byte intact and put the annotation on its own line
		// above instead. A per-line Before annotation still overrides block-
		// and file-level defaults (the suffix carries no annotation to beat it).
		line.Before = append(line.Before, modfile.Comment{Token: "//" + annotation})
	case n > 0:
		line.Suffix[n-1].Token = appendToComment(line.Suffix[n-1].Token, annotation)
	default:
		line.Suffix = append(line.Suffix, modfile.Comment{Token: "// " + annotation, Suffix: true})
	}
	return true
}

// rewriteToken replaces every "gomodjail:<policy>" field of a comment token
// with the given annotation, preserving surrounding text and whitespace.
// ok reports whether the token contained an annotation at all. The grammar
// must match gomoddirectivecomments exactly — one "//" trimmed off the whole
// token, fields split on Unicode whitespace, one more "//" trimmed per field —
// or SetPolicy would append a second annotation that loses to the first one
// on reparse (the parser takes the first match).
func rewriteToken(token, annotation string) (_ string, ok bool) {
	var b strings.Builder
	rest := token
	if slashes, found := strings.CutPrefix(rest, "//"); found {
		b.WriteString("//")
		rest = slashes
	}
	for i := 0; i < len(rest); {
		j := i + spanFunc(rest[i:], unicode.IsSpace)
		b.WriteString(rest[i:j])
		k := j + spanFunc(rest[j:], func(r rune) bool { return !unicode.IsSpace(r) })
		field := rest[j:k]
		if core := strings.TrimPrefix(field, "//"); strings.HasPrefix(core, namespace+":") {
			ok = true
			field = field[:len(field)-len(core)] + annotation
		}
		b.WriteString(field)
		i = k
	}
	return b.String(), ok
}

// spanFunc returns the length of the leading run of s whose runes satisfy f.
func spanFunc(s string, f func(rune) bool) int {
	for i, r := range s {
		if !f(r) {
			return i
		}
	}
	return len(s)
}

// appendToComment appends the annotation to an existing suffix comment,
// normalizing trailing whitespace. Indirect requires never reach here (they
// get a Before comment so the `// indirect` suffix stays intact).
func appendToComment(token, annotation string) string {
	return strings.TrimRightFunc(token, unicode.IsSpace) + " " + annotation
}
