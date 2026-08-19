package secmemlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// checkCallbackEscapes runs the escape checks over the closure body, each scoped
// to the borrowed []byte parameters.
func checkCallbackEscapes(pass *analysis.Pass, acc accessor, sup *suppressor) {
	ast.Inspect(acc.fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			checkCallEscape(pass, acc, node, sup)
		case *ast.SendStmt:
			if refersToParam(node.Value, acc.params) && !sup.suppressed(pass, node.Pos()) {
				report(pass, node.Pos(), "borrowed secret bytes sent to a channel; they can outlive the closure")
			}
		case *ast.GoStmt:
			if goStmtLeaksParam(node.Call, acc.params) && !sup.suppressed(pass, node.Pos()) {
				report(pass, node.Pos(), "borrowed secret bytes handed to a goroutine; they can outlive the closure")
			}
		case *ast.AssignStmt:
			checkAssignEscape(pass, acc, node, sup)
		}
		return true
	})
}

// checkCallEscape handles the builtin conversions/calls (string, append, copy)
// and the dangerous-sink table.
func checkCallEscape(pass *analysis.Pass, acc accessor, call *ast.CallExpr, sup *suppressor) {
	if id, ok := call.Fun.(*ast.Ident); ok {
		switch id.Name {
		case "string":
			if len(call.Args) == 1 && refersToParam(call.Args[0], acc.params) && !sup.suppressed(pass, call.Pos()) {
				report(pass, call.Pos(), "string() copies borrowed secret bytes into a heap string")
			}
			return
		case "append":
			// refersToParam, not a bare *ast.Ident: append(dst, b[:n]...) is
			// the same escape written with a slice expression, and matching
			// only the identifier let it through.
			if call.Ellipsis.IsValid() && len(call.Args) >= 2 {
				if refersToParam(call.Args[len(call.Args)-1], acc.params) && !sup.suppressed(pass, call.Pos()) {
					report(pass, call.Pos(), "append(dst, borrowed...) copies borrowed secret bytes into an escaping slice")
				}
			}
			return
		case "panic":
			// The value is formatted into the runtime traceback and handed to
			// any recover() up the stack, both well outside the lease.
			if len(call.Args) == 1 && refersToParam(call.Args[0], acc.params) && !sup.suppressed(pass, call.Pos()) {
				report(pass, call.Pos(), "panic() puts borrowed secret bytes in the traceback and in any recover()")
			}
			return
		case "copy":
			if len(call.Args) == 2 && refersToParam(call.Args[1], acc.params) && !sup.suppressed(pass, call.Pos()) {
				report(pass, call.Pos(), "copy() moves borrowed secret bytes out of the closure")
			}
			return
		}
	}
	checkSink(pass, acc, call, sup)
}

// checkAssignEscape flags assigning a borrowed slice to a variable declared
// outside the closure. A := that declares a new inner variable is not itself an
// escape.
func checkAssignEscape(pass *analysis.Pass, acc accessor, stmt *ast.AssignStmt, sup *suppressor) {
	if stmt.Tok == token.DEFINE {
		return
	}
	for i, rhs := range stmt.Rhs {
		if i >= len(stmt.Lhs) || !refersToParam(rhs, acc.params) {
			continue
		}
		where, escapes := assignTargetEscapes(pass, stmt.Lhs[i], acc)
		if !escapes {
			continue
		}
		if !sup.suppressed(pass, stmt.Pos()) {
			report(pass, stmt.Pos(), "borrowed secret bytes assigned to "+where+"; they can outlive the closure")
		}
	}
}

// assignTargetEscapes reports whether assigning to target can put the value
// somewhere that outlives the closure, and names the shape for the diagnostic.
//
// Matching only *ast.Ident — which is all this check used to do — meant
// s.field = b, m[k] = b, out[i] = b and *p = b were every one of them silently
// clean. Those are not exotic; stashing a borrowed slice into a struct field is
// the most natural way to leak one.
func assignTargetEscapes(pass *analysis.Pass, target ast.Expr, acc accessor) (string, bool) {
	switch t := target.(type) {
	case *ast.ParenExpr:
		return assignTargetEscapes(pass, t.X, acc)

	case *ast.Ident:
		if t.Name == "_" {
			return "", false
		}
		obj := pass.TypesInfo.ObjectOf(t)
		if obj == nil || withinNode(obj.Pos(), acc.fn) {
			return "", false // an inner variable — it stays within the lease
		}
		return "a variable outside the closure", true

	case *ast.StarExpr:
		// Writing through a pointer: the pointee is chosen by whoever produced
		// the pointer, so it cannot be assumed to be inside the lease.
		return "a pointer target", true

	case *ast.SelectorExpr:
		if rootIsInnerValue(pass, t, acc) {
			return "", false
		}
		return "a struct field", true

	case *ast.IndexExpr:
		if rootIsInnerValue(pass, t, acc) {
			return "", false
		}
		return "a map or slice element", true
	}
	return "", false
}

// rootIsInnerValue reports whether expr is rooted at a variable declared inside
// the closure whose type cannot alias memory outside it.
//
// A local struct or array is genuinely inner: writing to its field or element
// keeps the bytes within the lease. A local pointer, slice or map is not — the
// variable is inner but what it refers to need not be, so those still escape.
func rootIsInnerValue(pass *analysis.Pass, expr ast.Expr, acc accessor) bool {
	root := rootIdent(expr)
	if root == nil {
		return false
	}
	obj := pass.TypesInfo.ObjectOf(root)
	if obj == nil || !withinNode(obj.Pos(), acc.fn) {
		return false
	}
	switch pass.TypesInfo.TypeOf(root).Underlying().(type) {
	case *types.Struct, *types.Array:
		return true
	}
	return false
}

// rootIdent walks selector/index/paren chains down to the identifier they are
// rooted at, or nil if the expression is not rooted at a plain identifier.
func rootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.ParenExpr:
			expr = e.X
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// checkSink flags borrowed bytes passed to a heap-copying or logging stdlib sink.
func checkSink(pass *analysis.Pass, acc accessor, call *ast.CallExpr, sup *suppressor) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	name, reason := sinkFor(pass, sel)
	if reason == "" {
		return
	}
	for _, arg := range call.Args {
		if refersToParam(arg, acc.params) {
			if !sup.suppressed(pass, call.Pos()) {
				report(pass, call.Pos(), fmt.Sprintf("borrowed secret bytes passed to %s; %s", name, reason))
			}
			return // one finding per call is enough
		}
	}
}

// sinkFor resolves a selector to a denylisted sink, returning its display name
// and the reason it is dangerous, or "" if it is not a sink.
func sinkFor(pass *analysis.Pass, sel *ast.SelectorExpr) (name, reason string) {
	if x, ok := sel.X.(*ast.Ident); ok {
		if pkg, ok := pass.TypesInfo.Uses[x].(*types.PkgName); ok {
			key := pkg.Imported().Path() + "." + sel.Sel.Name
			if r, ok := sinks[key]; ok {
				return key, r
			}
		}
	}
	// Logger-receiver form: sl.Info(b), l.Printf("%s", b),
	// slog.Default().Info("", "k", b). The package table above is keyed by
	// "import/path.Func" and matches only a call qualified by a package name,
	// so every logging METHOD reached this point unflagged. Resolved by
	// receiver type so an unrelated Info method on some other type is not
	// swept in.
	if loggerMethods[sel.Sel.Name] {
		recv := pass.TypesInfo.TypeOf(sel.X)
		if typeFromPkg(recv, "log/slog") {
			return "log/slog.Logger." + sel.Sel.Name, "it logs the secret"
		}
		if typeFromPkg(recv, "log") {
			return "log.Logger." + sel.Sel.Name, "it logs the secret"
		}
	}

	// Encoder-receiver form, e.g. base64.StdEncoding.EncodeToString(borrowed).
	if sel.Sel.Name == "EncodeToString" || sel.Sel.Name == "Encode" {
		if typeFromPkg(pass.TypesInfo.TypeOf(sel.X), "encoding/base64") {
			return "encoding/base64." + sel.Sel.Name, "it copies the secret to the heap outside the buffer lifecycle"
		}
	}
	return "", ""
}

func typeFromPkg(t types.Type, path string) bool {
	switch tt := t.(type) {
	case *types.Named:
		return tt.Obj() != nil && tt.Obj().Pkg() != nil && tt.Obj().Pkg().Path() == path
	case *types.Pointer:
		return typeFromPkg(tt.Elem(), path)
	}
	return false
}
