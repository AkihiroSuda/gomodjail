package analyzer

import (
	"context"
	"flag"
	"go/ast"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

type Opts struct {
	Flags flag.FlagSet
}

func New(ctx context.Context, opts Opts) (*analysis.Analyzer, error) {
	a := &analysis.Analyzer{
		Name:             "gomodjail",
		Doc:              "gomodjail static analyzer",
		URL:              "https://github.com/AkihiroSuda/gomodjail",
		Flags:            opts.Flags,
		Run:              run,
		RunDespiteErrors: false,
	}
	return a, nil
}

func run(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		filename := pass.Fset.Position(f.Pos()).Filename
		slog.Debug("analyzing file", "filename", filename)
		if err := analyzeFile(pass, f, filename); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func analyzeFile(pass *analysis.Pass, f *ast.File, filename string) error {
	// Check the file name
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".s":
		pass.Report(analysis.Diagnostic{
			Pos:     f.Pos(),
			End:     f.End(),
			Message: "assembly file detected",
		})
	case ".c", ".h":
		pass.Report(analysis.Diagnostic{
			Pos:     f.Pos(),
			End:     f.End(),
			Message: "C source file detected",
		})
	}

	// Check imports
	for _, imp := range f.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		switch importPath {
		case "C", "unsafe", "reflect", "plugin":
			pass.Report(analysis.Diagnostic{
				Pos:     imp.Pos(),
				End:     imp.End(),
				Message: "unsafe package imported: " + imp.Path.Value,
			})
		}
	}

	// Check comment directives
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				pass.Report(analysis.Diagnostic{
					Pos:     c.Pos(),
					End:     c.End(),
					Message: "use of //go:linkname directive detected",
				})
			}
		}
	}

	return nil
}
