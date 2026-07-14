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
			if call.Ellipsis.IsValid() && len(call.Args) >= 2 {
				if last, ok := call.Args[len(call.Args)-1].(*ast.Ident); ok && acc.params[last.Name] && !sup.suppressed(pass, call.Pos()) {
					report(pass, call.Pos(), "append(dst, borrowed...) copies borrowed secret bytes into an escaping slice")
				}
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
		lhs, ok := stmt.Lhs[i].(*ast.Ident)
		if !ok || lhs.Name == "_" {
			continue
		}
		obj := pass.TypesInfo.ObjectOf(lhs)
		if obj == nil || withinNode(obj.Pos(), acc.fn) {
			continue // an inner variable — it stays within the lease
		}
		if !sup.suppressed(pass, stmt.Pos()) {
			report(pass, stmt.Pos(), "borrowed secret bytes assigned to a variable outside the closure; they can outlive it")
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
