package secmemlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ast/inspector"
)

// strict enables the opt-in checks. They are off by default because they are
// heuristic and higher-noise than the escape/reentrancy checks: a consumer opts
// in with `-secmemlint.strict` (go vet) or the analyzer flag.
var strict bool //nolint:gochecknoglobals // go/analysis flag state is package-level by convention.

func init() { //nolint:gochecknoinits // registers the analyzer's -strict flag.
	Analyzer.Flags.BoolVar(&strict, "strict", false,
		"enable opt-in checks: N1 secret-named strings and L1 missing defer Destroy")
}

// secretNameRE matches identifier names that are high-confidence secrets — names
// that should almost never be held in a plain string.
var secretNameRE = regexp.MustCompile( //nolint:gochecknoglobals // immutable.
	`(?i)^(` +
		`password|passwd|passphrase|` +
		`secret|` +
		`token|api_?key|` +
		`priv_?key|private_?key|` +
		`credential|credentials|` +
		`auth_?token|access_?token|refresh_?token|` +
		`bearer|jwt|` +
		`hmac_?secret|signing_?key|master_?key|` +
		`enc_?key|encryption_?key|decryption_?key|` +
		`tls_?key|ssh_?key|pgp_?key|gpg_?key` +
		`)$`)

// ownedTypes are the secmem / secmem-crypto types whose values own a locked
// allocation and must be Destroyed by their owner.
var ownedTypes = map[string]bool{ //nolint:gochecknoglobals // immutable.
	"SecureBuffer": true, "SecureArena": true,
	"Ed25519Signer": true, "ECDSASigner": true, "RSASigner": true,
	"X25519Key": true, "MLKEM768Key": true,
}

// ---------------------------------------------------------------------------
// N1: a secret-named identifier held in a plain string.
// ---------------------------------------------------------------------------

func checkSecretNamedStrings(pass *analysis.Pass, insp *inspector.Inspector, sup *suppressor) {
	nodes := []ast.Node{(*ast.ValueSpec)(nil), (*ast.Field)(nil), (*ast.AssignStmt)(nil)}
	insp.Preorder(nodes, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, name := range node.Names {
				reportIfSecretString(pass, name, sup)
			}
		case *ast.Field:
			for _, name := range node.Names {
				reportIfSecretString(pass, name, sup)
			}
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE {
				return
			}
			for _, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					reportIfSecretString(pass, id, sup)
				}
			}
		}
	})
}

func reportIfSecretString(pass *analysis.Pass, name *ast.Ident, sup *suppressor) {
	if name.Name == "_" || !secretNameRE.MatchString(name.Name) {
		return
	}
	obj := pass.TypesInfo.ObjectOf(name)
	if obj == nil || !isStringType(obj.Type()) {
		return
	}
	if sup.suppressed(pass, name.Pos()) {
		return
	}
	report(pass, name.Pos(), fmt.Sprintf(
		"%q is a secret-named identifier held in a plain string; store it in a *secmem.SecureBuffer",
		name.Name))
}

func isStringType(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.String
}

// ---------------------------------------------------------------------------
// L1: a locally constructed secmem resource that is never Destroyed or handed off.
// ---------------------------------------------------------------------------

func checkMissingDestroy(pass *analysis.Pass, insp *inspector.Inspector, sup *suppressor) {
	insp.WithStack([]ast.Node{(*ast.AssignStmt)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		assign := n.(*ast.AssignStmt)
		// Only handle `x := call(...)` / `x, err := call(...)` — a single call RHS.
		if len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isLibraryCall(pass, call) {
			return true
		}
		body := enclosingBody(stack)
		if body == nil {
			return true
		}
		for _, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			obj := pass.TypesInfo.ObjectOf(id)
			if obj == nil || !isOwnedResource(obj.Type()) {
				continue
			}
			// Only reason about a variable declared within the body we scan.
			// A variable declared in an outer scope (e.g. `var buf`) and assigned
			// inside a Scope/ScrubErr closure is owned and released by that outer
			// scope, which this innermost-body scan cannot see.
			if !withinNode(obj.Pos(), body) {
				continue
			}
			if resourceLeaks(pass, body, id, obj) && !sup.suppressed(pass, assign.Pos()) {
				report(pass, id.Pos(), fmt.Sprintf(
					"%s is never Destroyed or handed off; add `defer %s.Destroy()` (or return/pass it to transfer ownership)",
					id.Name, id.Name))
			}
		}
		return true
	})
}

// isOwnedResource reports whether t is a pointer to a secmem / secmem-crypto
// owned type (one with a Destroy the owner is responsible for).
func isOwnedResource(t types.Type) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	pkg := named.Obj().Pkg().Path()
	return (pkg == secmemPkg || pkg == cryptoPkg) && ownedTypes[named.Obj().Name()]
}

// isLibraryCall reports whether call resolves to a function declared in secmem or
// secmem-crypto — so we know the returned resource is freshly owned by the caller.
func isLibraryCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	var id *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.Ident:
		id = fun
	default:
		return false
	}
	fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	pkg := fn.Pkg().Path()
	return pkg == secmemPkg || pkg == cryptoPkg
}

// resourceLeaks reports whether obj (defined at def) is, within body, never
// Destroyed and never handed off — a create-and-forget leak. Any use of obj that
// is not a method call on it (passed as an argument, returned, aliased, &obj) is
// treated as a hand-off, so the check does not fire when ownership transfers.
func resourceLeaks(pass *analysis.Pass, body *ast.BlockStmt, def *ast.Ident, obj types.Object) bool {
	destroyed := false
	receivers := make(map[*ast.Ident]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || pass.TypesInfo.ObjectOf(id) != obj {
			return true
		}
		receivers[id] = true
		if sel.Sel.Name == "Destroy" {
			destroyed = true
		}
		return true
	})
	if destroyed {
		return false
	}
	handedOff := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || pass.TypesInfo.ObjectOf(id) != obj || id == def || receivers[id] {
			return true
		}
		handedOff = true
		return false
	})
	return !handedOff
}

// enclosingBody returns the body of the innermost function (decl or literal)
// enclosing the node at the top of stack, or nil.
func enclosingBody(stack []ast.Node) *ast.BlockStmt {
	for i := len(stack) - 1; i >= 0; i-- {
		switch fn := stack[i].(type) {
		case *ast.FuncDecl:
			return fn.Body
		case *ast.FuncLit:
			return fn.Body
		}
	}
	return nil
}
