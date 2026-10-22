package secmemlint

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// exposeMethods names, per package, the methods that hand the caller a Go
// string copy of the secret. They are E4 sinks on the call itself rather than
// on a tainted argument: the copy is made inside the library, out of reach of
// the escape scan, and is exactly the immutable heap string E1 reports for
// string(b) inside a closure.
var exposeMethods = map[string]map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	secmemPkg: {"ExposeString": true},
}

// checkExposeCalls reports every reference to an exposing method — a call, a
// method value (f := buf.ExposeString) or a method expression — once, where it
// is written. A deliberate egress is suppressed on that line like any other
// finding.
func (c *checker) checkExposeCalls(insp *inspector.Inspector) {
	insp.Preorder([]ast.Node{(*ast.SelectorExpr)(nil)}, func(n ast.Node) {
		sel := n.(*ast.SelectorExpr)
		selection, ok := c.pass.TypesInfo.Selections[sel]
		if !ok || selection.Kind() == types.FieldVal {
			return
		}
		m, ok := selection.Obj().(*types.Func)
		if !ok || !isExposeMethod(m) {
			return
		}
		c.report(sel.Sel.Pos(),
			m.Name()+" copies the secret into an immutable heap string that can never be wiped; borrow it with WithBytes / WithBytesErr, or suppress at a reviewed boundary")
	})
}

// isExposeMethod reports whether m is an exposing method: one of the known
// methods on a secmem type, or — the same interface heuristic as for the
// borrowing accessors — a method of that name and shape (no parameters,
// returning (string, error)) declared on an interface, since a
// *secmem.SecureBuffer behind an interface still makes the copy.
func isExposeMethod(m *types.Func) bool {
	if m.Pkg() == nil {
		return false
	}
	if names, ok := exposeMethods[m.Pkg().Path()]; ok {
		return names[m.Name()]
	}
	if !exposeMethods[secmemPkg][m.Name()] {
		return false
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || !types.IsInterface(sig.Recv().Type()) {
		return false
	}
	res := sig.Results()
	return sig.Params().Len() == 0 && res.Len() == 2 &&
		isStringType(res.At(0).Type()) && isErrorType(res.At(1).Type())
}
