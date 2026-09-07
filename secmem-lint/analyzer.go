package secmemlint

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	secmemPkg  = "github.com/deadpoets/secmem"
	cryptoPkg  = "github.com/deadpoets/secmem/secmem-crypto"
	diagPrefix = "secmem-lint: "
)

// Analyzer is the secmem-lint analysis pass. It is exported so it can be driven
// by cmd/secmem-lint (singlechecker, for `go vet -vettool`) or embedded as a
// golangci-lint module plugin.
var Analyzer = &analysis.Analyzer{ //nolint:gochecknoglobals // go/analysis convention: the analyzer is an exported package-level var.
	Name:     "secmemlint",
	Doc:      "flags secret material escaping a secmem borrowing closure",
	URL:      "https://github.com/deadpoets/secmem/tree/main/secmem-lint",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	insp, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, errors.New("secmem-lint: missing inspect analyzer result")
	}
	sup := newSuppressor(pass)

	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		acc, ok := borrowAccessor(pass, n.(*ast.CallExpr))
		if !ok {
			return
		}
		checkCallbackEscapes(pass, acc, sup)
		checkReentrancy(pass, acc, sup)
	})
	if strict {
		checkSecretNamedStrings(pass, insp, sup)
		checkMissingDestroy(pass, insp, sup)
	}
	return nil, nil //nolint:nilnil // go/analysis Run returns (nil result, nil error) when it has no Result to publish.
}

// accessor is a recognized secmem borrowing-closure call:
// recv.Method(func(p []byte) { ... }).
//
// Both fields identify things by types.Object rather than by name or AST shape.
// Names are the wrong key twice over: a receiver written as a field selector
// (s.buf) is not an identifier at all, and a borrowed parameter's name can be
// shadowed by an unrelated variable that happens to match.
type accessor struct {
	recv   []types.Object        // receiver identity chain, nil if undecidable
	fn     *ast.FuncLit          // the borrowing closure
	params map[types.Object]bool // its []byte parameters (the borrowed slices)
}

// borrowAccessor reports whether call is a secmem borrowing accessor and, if so,
// returns the closure and the names of its borrowed []byte parameters. Matching
// is type-aware: the method must be declared on a secmem (or secmem-crypto) type,
// so an unrelated WithBytes on some other library's type is not flagged.
func borrowAccessor(pass *analysis.Pass, call *ast.CallExpr) (accessor, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return accessor{}, false
	}
	selection, ok := pass.TypesInfo.Selections[sel]
	if !ok {
		return accessor{}, false
	}
	m, ok := selection.Obj().(*types.Func)
	if !ok || m.Pkg() == nil || !isBorrowMethod(m.Pkg().Path(), sel.Sel.Name) {
		return accessor{}, false
	}
	var lit *ast.FuncLit
	for _, arg := range call.Args {
		if fl, ok := arg.(*ast.FuncLit); ok {
			lit = fl
			break
		}
	}
	if lit == nil {
		return accessor{}, false
	}
	params := byteSliceParams(pass, lit)
	if len(params) == 0 {
		return accessor{}, false
	}
	recv, _ := receiverKey(pass, sel.X)
	return accessor{recv: recv, fn: lit, params: params}, true
}

// receiverKey builds a comparison key for a receiver expression: the chain of
// objects from the root identifier through any field selections, so buf and
// s.buf and s.inner.buf each get a key that can be compared for identity.
//
// It reports false for shapes whose identity cannot be decided statically —
// index expressions, calls, type assertions. bufs[i] and bufs[j] are written
// alike and need not be the same buffer, and getBuf() twice need not return the
// same one, so treating them as equal would be a false positive on a linter
// whose findings block a build.
func receiverKey(pass *analysis.Pass, expr ast.Expr) ([]types.Object, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		obj := pass.TypesInfo.ObjectOf(e)
		if obj == nil {
			return nil, false
		}
		return []types.Object{obj}, true

	case *ast.ParenExpr:
		return receiverKey(pass, e.X)

	case *ast.StarExpr:
		// (*p).WithBytes(...) names the same buffer as p.WithBytes(...).
		return receiverKey(pass, e.X)

	case *ast.SelectorExpr:
		base, ok := receiverKey(pass, e.X)
		if !ok {
			return nil, false
		}
		field := pass.TypesInfo.ObjectOf(e.Sel)
		if field == nil {
			return nil, false
		}
		key := make([]types.Object, 0, len(base)+1)
		key = append(key, base...)
		return append(key, field), true
	}
	return nil, false
}

// sameReceiver reports whether two receiver keys name the same buffer.
func sameReceiver(a, b []types.Object) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isBorrowMethod(pkgPath, method string) bool {
	switch pkgPath {
	case secmemPkg:
		return method == "WithBytes" || method == "WithBytesErr"
	case cryptoPkg:
		return method == "WithScalar" || method == "WithSeed" || method == "WithDER"
	}
	return false
}

// byteSliceParams returns the closure's []byte parameters — the borrowed slices
// whose escape the checks track.
func byteSliceParams(pass *analysis.Pass, fn *ast.FuncLit) map[types.Object]bool {
	objs := make(map[types.Object]bool)
	if fn.Type == nil || fn.Type.Params == nil {
		return objs
	}
	for _, field := range fn.Type.Params.List {
		if !isByteSlice(field.Type) {
			continue
		}
		for _, n := range field.Names {
			if n.Name == "_" {
				continue
			}
			if obj := pass.TypesInfo.ObjectOf(n); obj != nil {
				objs[obj] = true
			}
		}
	}
	return objs
}

func isByteSlice(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := arr.Elt.(*ast.Ident)
	return ok && (elt.Name == "byte" || elt.Name == "uint8")
}

// report emits a finding with the shared secmem-lint prefix.
func report(pass *analysis.Pass, pos token.Pos, msg string) {
	pass.Report(analysis.Diagnostic{Pos: pos, Message: diagPrefix + msg})
}

// --- suppression: //nolint:secmem-lint (or a bare //nolint) on the finding line ---

type suppressor struct {
	lines map[string]bool
}

func newSuppressor(pass *analysis.Pass) *suppressor {
	s := &suppressor{lines: make(map[string]bool)}
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if nolintApplies(c.Text) {
					p := pass.Fset.Position(c.Pos())
					s.lines[lineKey(p.Filename, p.Line)] = true
				}
			}
		}
	}
	return s
}

func (s *suppressor) suppressed(pass *analysis.Pass, pos token.Pos) bool {
	p := pass.Fset.Position(pos)
	return s.lines[lineKey(p.Filename, p.Line)]
}

func lineKey(file string, line int) string {
	return file + ":" + strconv.Itoa(line)
}

// nolintApplies reports whether a //nolint directive covers secmem-lint: either a
// bare //nolint, or //nolint:<list> where the list contains secmem-lint.
func nolintApplies(comment string) bool {
	t := strings.TrimSpace(strings.TrimPrefix(comment, "//"))
	if t == "nolint" {
		return true
	}
	if !strings.HasPrefix(t, "nolint:") {
		return false
	}
	list := strings.TrimPrefix(t, "nolint:")
	if i := strings.IndexByte(list, ' '); i >= 0 {
		list = list[:i] // drop any trailing "// explanation"
	}
	for _, name := range strings.Split(list, ",") {
		if strings.TrimSpace(name) == "secmem-lint" {
			return true
		}
	}
	return false
}

// --- shared AST helpers ---

// refersToParam reports whether expr is (a paren/slice around) a borrowed param.
// It deliberately does not recurse into calls, so len(p) or f(p) is not itself a
// direct reference to the borrowed slice.
func refersToParam(pass *analysis.Pass, expr ast.Expr, params map[types.Object]bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return params[pass.TypesInfo.ObjectOf(e)]
	case *ast.ParenExpr:
		return refersToParam(pass, e.X, params)
	case *ast.SliceExpr:
		return refersToParam(pass, e.X, params)
	}
	return false
}

// goStmtLeaksParam reports whether a go statement hands a borrowed param to the
// new goroutine — captured by a closure body or passed as an argument.
//
// The capture scan resolves each identifier to its object rather than comparing
// names. A goroutine that declares its own b, or ranges over one, is not
// touching the borrowed slice at all, and matching on the name alone reported it
// as a leak.
func goStmtLeaksParam(pass *analysis.Pass, call *ast.CallExpr, params map[types.Object]bool) bool {
	if call == nil {
		return false
	}
	for _, arg := range call.Args {
		if refersToParam(pass, arg, params) {
			return true
		}
	}
	lit, ok := call.Fun.(*ast.FuncLit)
	if !ok || lit.Body == nil {
		return false
	}
	leaked := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if leaked {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && params[pass.TypesInfo.ObjectOf(id)] {
			leaked = true
		}
		return !leaked
	})
	return leaked
}

// withinNode reports whether pos falls inside node's source range.
func withinNode(pos token.Pos, node ast.Node) bool {
	return pos >= node.Pos() && pos < node.End()
}
