// Copyright 2023 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// This file is a copy of Capslock's call-rewriting pre-pass:
// rewriteCallsToSort and rewriteCallsToOnceDoEtc (and their helpers) from
// github.com/google/capslock@v0.3.2 analyzer/rewrite.go, plus the matcher
// types they use from analyzer/util.go. Capslock does not export them.
//
// The copy is byte-for-byte EXCEPT for clearly-marked deviations — the
// "gomodjail: deviation" comments (rewriteCallsToSort reports how many
// matching call sites it had to leave unrewritten; see warmUpRewrites) and
// a few //nolint annotations. When re-syncing against a new Capslock
// version, diff against upstream and re-apply exactly those deviations.
//
// Why the copy exists: Capslock applies these rewrites to the shared ASTs of
// the loaded packages, in place, at the start of every analysis. The rewrite
// is idempotent — a rewritten call site never matches a matcher again — but
// it is not concurrency-safe. gomodjail runs one analysis per confined
// module over a shared package load; to run those analyses concurrently, the
// warm-up below applies the same rewrites to every loaded package first, so
// the analyses' own rewrite passes find nothing left to mutate and the
// shared ASTs are only read.
//
// The rewriting itself MUST stay behaviorally identical to the pinned
// Capslock version:
// if it rewrote fewer call sites, the concurrent analyses would race on the
// remainder; if it rewrote more (or differently), it would change Capslock's
// call-graph precision. TestRewritePinning pins the upstream sources and
// fails on any Capslock bump that touches them, making the re-sync of this
// file a visible, reviewable event.

package capslock

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"unsafe"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

// warmUpRewrites applies Capslock's AST call-rewriting to pkgs and all their
// transitive dependencies. Not concurrency-safe; call it once, before any
// concurrent analyzer.GetCapabilityInfo calls over (subsets of) pkgs.
//
// residual is the number of matching call sites the sort rewrite had to
// leave in place (e.g. `sort.Sort(nil)`: valid Go, its method-set lookup
// fails, and it only survives in dead code — which is still loaded and
// walked). Capslock's own rewrite pass writes shared type information for
// such a site on EVERY visit before it gives up, so when residual > 0 the
// later analyses are NOT read-only and must not run concurrently. The other
// give-up paths (a non-statement position, or a non-function `Once.Do`-family
// argument) bail out before any write and need no counting.
func warmUpRewrites(pkgs []*packages.Package) (residual int) {
	residual = rewriteCallsToSort(pkgs)
	rewriteCallsToOnceDoEtc(pkgs)
	return residual
}

// operandMode has the same layout as types.operandMode.
type operandMode byte

const (
	noValueMode  operandMode = 1
	constantMode operandMode = 4
	valueMode    operandMode = 7
)

// constructTypeAndValue constructs a types.TypeAndValue.  These are used in
// the types.Info.Types map to store the known types of expressions, and the
// values of constant expressions.
func constructTypeAndValue(mode operandMode, t types.Type, v constant.Value) types.TypeAndValue {
	// The mode field of types.TypeAndValue is not exported, so we make our own
	// copy of the type definition, and use unsafe conversion to get the type we
	// want.
	tv := struct {
		mode  operandMode
		Types types.Type
		Value constant.Value
	}{mode, t, v}
	return *(*types.TypeAndValue)(unsafe.Pointer(&tv))
}

// typeAndValueForResults constructs a TypeAndValue corresponding to the return
// values of a function.
func typeAndValueForResults(results *types.Tuple) types.TypeAndValue {
	if results == nil {
		// Case 1: the function has no return values.
		return constructTypeAndValue(noValueMode, results, nil)
	}
	if results.Len() == 1 {
		// Case 2: the function has a single return value.
		return constructTypeAndValue(valueMode, results.At(0).Type(), nil)
	}
	// Case 3: the function returns a tuple of more than one value.
	return constructTypeAndValue(valueMode, results, nil)
}

// zeroLiteral creates and returns a zero literal of type int, and adds its
// type information to typeInfo.Types.
func zeroLiteral(typeInfo *types.Info) ast.Expr {
	expr := &ast.BasicLit{Kind: token.INT, Value: "0"}
	typeInfo.Types[expr] = constructTypeAndValue(constantMode, types.Typ[types.Int], constant.MakeInt64(0))
	return expr
}

// selectionForMethod finds the Selection object for the given method.
func selectionForMethod(typ types.Type, name string) *types.Selection {
	var ms *types.MethodSet = types.NewMethodSet(typ) //nolint:staticcheck // verbatim upstream copy
	// The package is not needed for exported methods, so we can pass nil for the
	// package parameter of Lookup.
	sel := ms.Lookup(nil, name)
	return sel
}

// rewriteCallsToSort iterates through the packages in pkgs, including all
// transitively-imported packages, and finds calls to sort.Sort, sort.Stable,
// and sort.IsSorted, which each have a sort.Interface parameter.  We replace
// each of these calls with a set of calls to each of the interface methods
// individually (Len, Less, and Swap.)  e.g., this code:
//
//	sort.Sort(xs)
//
// would be replaced with:
//
//	xs.Len()
//	xs.Less(0,0)
//	xs.Swap(0,0)
//
// This improves the precision of the callgraph the analysis produces.  The
// analysis produces a set of possible dynamic types for the sort.Interface
// value, and adds a callgraph edge to the methods for each of those.
//
// Without this change to the callgraph, we would get paths to the
// sort.Interface methods for every possible dynamic type for all the values
// passed to the same sort function anywhere in the program, which can result
// in a large number of false positives.
//
// gomodjail: deviation from the upstream copy — the function reports how
// many matching call sites it could not rewrite (see warmUpRewrites).
func rewriteCallsToSort(pkgs []*packages.Package) (residual int) {
	forEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, node := range file.Decls {
				var pre astutil.ApplyFunc //nolint:staticcheck // verbatim upstream copy
				pre = func(c *astutil.Cursor) bool {
					// If the current node, c.Node(), is a call to sort.Sort (or
					// sort.Stable or sort.IsSorted), replace it with calls to
					// obj.Less, obj.Swap, and obj.Len, where obj is the argument
					// that was passed to sort.
					if _, ok := c.Node().(ast.Stmt); !ok {
						// c.Node() is not a statement.
						return true
					}
					canRewrite := false
					switch c.Parent().(type) {
					case *ast.BlockStmt, *ast.CaseClause, *ast.LabeledStmt:
						canRewrite = true
					case *ast.CommClause:
						canRewrite = c.Index() >= 0
					}
					if !canRewrite {
						// The statement is in a position in the syntax tree where it
						// can't be replaced with a block or with multiple statements, so
						// we give up.
						return true
					}

					obj := isCallToSort(p.TypesInfo, c.Node())
					if obj == nil {
						// This was not a call to a sort function.
						//
						// We always return true from this function, because the return
						// value indicates to astutil.Apply whether to keep searching.
						return true
					}
					// Less and Swap each take two integer arguments.  The values aren't
					// important for our callgraph analysis -- we do not look at values
					// to determine which way an if statement branches, for example --
					// so we just use two zeroes.
					args1 := []ast.Expr{zeroLiteral(p.TypesInfo), zeroLiteral(p.TypesInfo)}
					args2 := []ast.Expr{zeroLiteral(p.TypesInfo), zeroLiteral(p.TypesInfo)}
					// Create a block with three statements which call Less, Swap,
					// and Len.  Replace the current node with this block.
					s1 := statementCallingMethod(p.TypesInfo, obj, "Less", args1)
					s2 := statementCallingMethod(p.TypesInfo, obj, "Swap", args2)
					s3 := statementCallingMethod(p.TypesInfo, obj, "Len", nil)
					if s1 == nil || s2 == nil || s3 == nil {
						// We did not succeed in creating these statements.
						residual++ // gomodjail: deviation from the upstream copy
						return true
					}
					c.Replace(&ast.BlockStmt{List: []ast.Stmt{s1, s2, s3}})
					return true
				}
				astutil.Apply(node, pre, nil)
			}
		}
	})
	return residual // gomodjail: deviation from the upstream copy
}

// rewriteCallsToOnceDoEtc is similar to rewriteCallsToSort.  It finds calls
// to some standard-library functions and methods which have a function
// parameter, and changes those calls to call the function argument directly
// instead.
//
// e.g. this code:
//
//	var myonce *sync.Once = ...
//	myonce.Do(fn)
//
// would be replaced with:
//
//	var myonce *sync.Once = ...
//	fn()
func rewriteCallsToOnceDoEtc(pkgs []*packages.Package) {
	forEachPackageIncludingDependencies(pkgs, func(p *packages.Package) {
		for _, file := range p.Syntax {
			for _, node := range file.Decls {
				var pre astutil.ApplyFunc //nolint:staticcheck // verbatim upstream copy
				pre = func(c *astutil.Cursor) bool {
					obj := isCallToOnceDoEtc(p.TypesInfo, c.Node())
					if obj == nil {
						// This was not a call to a relevant function or method.
						return true
					}
					fnType, ok := types.Unalias(p.TypesInfo.TypeOf(obj)).(*types.Signature)
					if !ok {
						// The argument does not appear to be a function.
						return true
					}
					// Create some arguments to pass to the function.  The parameters
					// must all be integers.
					params := fnType.Params()
					args := make([]ast.Expr, params.Len())
					for i := range args {
						args[i] = zeroLiteral(p.TypesInfo)
					}
					c.Replace(
						statementCallingFunctionObject(p.TypesInfo, obj, args))
					return true
				}
				astutil.Apply(node, pre, nil)
			}
		}
	})
}

// isCallToSort checks if node is a statement calling sort.Sort, sort.Stable,
// or sort.IsSorted.  If so, it returns the argument to that function.
// Otherwise, it returns nil.
func isCallToSort(typeInfo *types.Info, node ast.Node) ast.Expr {
	expr, ok := node.(*ast.ExprStmt)
	if !ok {
		// Not a statement node.
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		// Not a function call.
		return nil
	}
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// The function to be called is not a selection, so it can't be a call to
		// the sort package.  (Unless the user has dot-imported "sort", but we
		// don't need to worry much about false negatives in unusual cases here.)
		return nil
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand-side of the selection is not a plain identifier.
		return nil
	}
	pkgName, ok := typeInfo.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return nil
	}
	if pkgName.Imported().Path() != "sort" {
		// The package isn't "sort".  (We use Imported().Path() because the import
		// name could be misleading, e.g.:
		// import (
		//   sort "os"
		// )
		return nil
	}
	if name := callee.Sel.Name; name != "Sort" && name != "Stable" && name != "IsSorted" {
		// This isn't one of the functions we're looking for.
		return nil
	}
	if len(call.Args) != 1 {
		// The function call doesn't have one argument.
		return nil
	}
	return call.Args[0]
}

// isCallToOnceDoEtc checks if node is a statement calling a function or method
// like (*sync.Once).Do.  If so, it returns the function-typed argument to that
// function.  Otherwise, it returns nil.
func isCallToOnceDoEtc(typeInfo *types.Info, node ast.Node) ast.Expr {
	expr, ok := node.(*ast.ExprStmt)
	if !ok {
		// Not a statement node.
		return nil
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		// Not a call expression.
		return nil
	}
	for _, m := range functionsToRewrite {
		if e := m.match(typeInfo, call); e != nil {
			return e
		}
	}
	return nil
}

// statementCallingMethod constructs a statement that calls a method.  The
// receiver is recv, the method name is methodName, and the arguments passed
// to the call are in args.
//
// New AST structures that are created by statementCallingMethod are added
// to the Types, Selections and Uses fields of typeInfo as needed.  The
// expressions in methodName and args should already be in typeInfo.
//
// If the statement cannot be created, returns nil.
func statementCallingMethod(typeInfo *types.Info, recv ast.Expr, methodName string, args []ast.Expr) *ast.ExprStmt {
	// Construct an ast node for the method name, and add it to typeInfo.Uses.
	methodIdent := ast.NewIdent(methodName)
	var selection *types.Selection = selectionForMethod(typeInfo.TypeOf(recv), methodName) //nolint:staticcheck // verbatim upstream copy
	if selection == nil {
		// We did not find the desired method for this type.  recv might be an
		// untyped nil.
		return nil
	}
	typeInfo.Uses[methodIdent] = selection.Obj()
	// Construct an ast node for the selection (e.g. "v.M"), and add it to
	// typeInfo.Selections and typeInfo.Types.
	selectorExpr := &ast.SelectorExpr{X: recv, Sel: methodIdent}
	typeInfo.Selections[selectorExpr] = selection
	typeInfo.Types[selectorExpr] = constructTypeAndValue(valueMode, selection.Type(), nil)
	// Construct an ast node for the call (e.g. "v.M(arg1, arg2)") and add it
	// to typeInfo.Types.
	callExpr := &ast.CallExpr{Fun: selectorExpr, Args: append([]ast.Expr(nil), args...)}
	typeInfo.Types[callExpr] = typeAndValueForResults(types.Unalias(selection.Type()).(*types.Signature).Results())
	// Return an ast node for a statement which is just the call.  No type
	// information is needed for statements.
	return &ast.ExprStmt{X: callExpr}
}

// statementCallingFunctionObject constructs a statement that calls a function.
//
// New AST structures that are created by statementCallingFunctionObject are
// added to the Types fields of typeInfo as needed.  The expressions in fn and
// args should already be in typeInfo.
func statementCallingFunctionObject(typeInfo *types.Info, fn ast.Expr, args []ast.Expr) *ast.ExprStmt {
	// Construct an ast node for the call and add it to typeInfo.Types.
	callExpr := &ast.CallExpr{Fun: fn, Args: append([]ast.Expr(nil), args...)}
	fnType := typeInfo.TypeOf(fn)
	fnTypeSignature, _ := types.Unalias(fnType).(*types.Signature)
	if fnTypeSignature == nil {
		panic(fmt.Sprintf("cannot get type signature of function %v", fn))
	}
	typeInfo.Types[callExpr] = typeAndValueForResults(fnTypeSignature.Results())
	// Return an ast node for a statement which is just the call.  No type
	// information is needed for statements.
	return &ast.ExprStmt{X: callExpr}
}

// The declarations below are copied from capslock analyzer/util.go.

// functionsToRewrite lists the functions and methods like (*sync.Once).Do that
// rewriteCallsToOnceDoEtc will rewrite to calls to their arguments.
var functionsToRewrite = []matcher{
	&methodMatcher{
		pkg:                         "sync",
		typeName:                    "Once",
		methodName:                  "Do",
		functionTypedParameterIndex: 0,
	},
	&packageFunctionMatcher{
		pkg:                         "sort",
		functionName:                "Slice",
		functionTypedParameterIndex: 1,
	},
	&packageFunctionMatcher{
		pkg:                         "sort",
		functionName:                "SliceStable",
		functionTypedParameterIndex: 1,
	},
	&methodMatcher{
		pkg:                         "golang.org/x/sync/errgroup",
		typeName:                    "Group",
		methodName:                  "Go",
		functionTypedParameterIndex: 0,
	},
	&methodMatcher{
		pkg:                         "sync",
		typeName:                    "WaitGroup",
		methodName:                  "Go",
		functionTypedParameterIndex: 0,
	},
}

type matcher interface {
	// match checks if a CallExpr is a call to a particular function or method
	// that this object is looking for.  If it matches, it returns a particular
	// argument in the call that has a function type.  Otherwise it returns nil.
	match(*types.Info, *ast.CallExpr) ast.Expr
}

// packageFunctionMatcher objects match a package-scope function.
type packageFunctionMatcher struct {
	pkg                         string
	functionName                string
	functionTypedParameterIndex int
}

// methodMatcher objects match a method of some type.
type methodMatcher struct {
	pkg                         string
	typeName                    string
	methodName                  string
	functionTypedParameterIndex int
}

func (m *packageFunctionMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// The function to be called is not a selection, so it can't be a call to
		// the relevant package.  (Unless the user has dot-imported the package,
		// but we don't need to worry much about false negatives in unusual cases
		// here.)
		return nil
	}
	pkgIdent, ok := callee.X.(*ast.Ident)
	if !ok {
		// The left-hand side of the selection is not a plain identifier.
		return nil
	}
	pkgName, ok := typeInfo.Uses[pkgIdent].(*types.PkgName)
	if !ok {
		// The identifier does not refer to a package.
		return nil
	}
	if pkgName.Imported().Path() != m.pkg {
		// Not the right package.
		return nil
	}
	if name := callee.Sel.Name; name != m.functionName {
		// This isn't the function we're looking for.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The function call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// mayHaveSideEffects determines whether an expression might write to a
// variable or call a function.  It can have false positives.  It does not
// consider panicking to be a side effect, so e.g. index expressions do not
// have side effects unless one of its components do.
//
// This is used to determine whether we can delete the expression from the
// syntax tree in isCallToOnceDoEtc.
func mayHaveSideEffects(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.Ident, *ast.BasicLit:
		return false
	case nil:
		return false // we can reach a nil via *ast.SliceExpr
	case *ast.FuncLit:
		return false // a definition doesn't do anything on its own
	case *ast.CallExpr:
		return true
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if mayHaveSideEffects(elt) {
				return true
			}
		}
		return false
	case *ast.ParenExpr:
		return mayHaveSideEffects(e.X)
	case *ast.SelectorExpr:
		return mayHaveSideEffects(e.X)
	case *ast.IndexExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Index)
	case *ast.IndexListExpr:
		for _, idx := range e.Indices {
			if mayHaveSideEffects(idx) {
				return true
			}
		}
		return mayHaveSideEffects(e.X)
	case *ast.SliceExpr:
		return mayHaveSideEffects(e.X) ||
			mayHaveSideEffects(e.Low) ||
			mayHaveSideEffects(e.High) ||
			mayHaveSideEffects(e.Max)
	case *ast.TypeAssertExpr:
		return mayHaveSideEffects(e.X)
	case *ast.StarExpr:
		return mayHaveSideEffects(e.X)
	case *ast.UnaryExpr:
		return mayHaveSideEffects(e.X)
	case *ast.BinaryExpr:
		return mayHaveSideEffects(e.X) || mayHaveSideEffects(e.Y)
	case *ast.KeyValueExpr:
		return mayHaveSideEffects(e.Key) || mayHaveSideEffects(e.Value)
	}
	return true
}

func (m *methodMatcher) match(typeInfo *types.Info, call *ast.CallExpr) ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if mayHaveSideEffects(sel.X) {
		// The expression may be something like foo().Do(bar), which we can't
		// rewrite to a call to bar because then the analysis would not see the
		// call to foo.
		return nil
	}
	calleeType := typeInfo.TypeOf(sel.X)
	if calleeType == nil {
		return nil
	}
	if ptr, ok := types.Unalias(calleeType).(*types.Pointer); ok {
		calleeType = ptr.Elem()
	}
	named, ok := types.Unalias(calleeType).(*types.Named)
	if !ok {
		return nil
	}
	if named.Obj().Pkg() == nil {
		// Not in a package.
		return nil
	}
	if pkg := named.Obj().Pkg().Path(); pkg != m.pkg {
		// Not the right package.
		return nil
	}
	if named.Obj().Name() != m.typeName {
		// Not the right type.
		return nil
	}
	if name := sel.Sel.Name; name != m.methodName {
		// Not the right method.
		return nil
	}
	if len(call.Args) <= m.functionTypedParameterIndex {
		// The method call doesn't have enough arguments.
		return nil
	}
	return call.Args[m.functionTypedParameterIndex]
}

// forEachPackageIncludingDependencies calls fn exactly once for each package
// that is in pkgs or in the transitive dependencies of pkgs.
func forEachPackageIncludingDependencies(pkgs []*packages.Package, fn func(*packages.Package)) {
	visitedPackages := make(map[*packages.Package]struct{})
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if _, ok := visitedPackages[p]; ok {
			return
		}
		visitedPackages[p] = struct{}{}
		for _, p2 := range p.Imports {
			visit(p2)
		}
		fn(p)
	}
	for _, p := range pkgs {
		visit(p)
	}
}
