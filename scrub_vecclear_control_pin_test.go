package secmem

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// TestVecClearControl_IsScrubMinusTheClear pins the vector-clear proof's
// control to the code it is a control for. legacyWindowNoClear
// (scrub_vecclear_control_test.go) is a hand-written copy of Scrub's legacy
// body with one line left out, and a copy drifts: an extra call, a reordered
// defer, a different pin, and the control measures some other exit sequence
// while still reporting "residue survives". The two cannot share a helper —
// the whole point of the window is that nothing runs between fn's return and
// the clear — so this test compares their source instead: Scrub's statement
// list, less the nil guard (the control is never handed nil) and the deferred
// clearVectorRegs (the line under test), must print identically to the
// control's. Comments are not compared; statements are.
func TestVecClearControl_IsScrubMinusTheClear(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	scrub := funcBody(t, fset, "scrub_legacy.go", "Scrub")
	control := funcBody(t, fset, "scrub_vecclear_control_test.go", "legacyWindowNoClear")

	var kept []ast.Stmt
	removedNilGuard, removedClear := false, false
	for _, st := range scrub.List {
		if !removedNilGuard && isNilGuard(fset, st) {
			removedNilGuard = true
			continue
		}
		if isDeferredCallTo(st, "clearVectorRegs") {
			if removedClear {
				t.Fatal("Scrub defers clearVectorRegs more than once; the pin removes exactly one")
			}
			removedClear = true
			continue
		}
		kept = append(kept, st)
	}
	if !removedNilGuard {
		t.Fatal("Scrub's body no longer opens with the `if fn == nil { return }` guard this pin removes; update the pin with the control")
	}
	if !removedClear {
		t.Fatal("Scrub's body no longer defers clearVectorRegs; the control has nothing to be a control for")
	}

	want := printStmts(t, fset, kept)
	got := printStmts(t, fset, control.List)
	if want != got {
		t.Errorf("legacyWindowNoClear has drifted from Scrub minus the clear; the proof's control no longer replicates the window it controls for.\n--- Scrub, less the nil guard and the deferred clear:\n%s\n--- legacyWindowNoClear:\n%s", want, got)
	}
}

// funcBody parses file (no comments, so none are compared) and returns the
// body of the named top-level function.
func funcBody(t *testing.T, fset *token.FileSet, file, name string) *ast.BlockStmt {
	t.Helper()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			if fn.Body == nil {
				t.Fatalf("%s: %s has no body", file, name)
			}
			return fn.Body
		}
	}
	t.Fatalf("%s: no top-level func %s", file, name)
	return nil
}

// isNilGuard matches `if fn == nil { return }`.
func isNilGuard(fset *token.FileSet, st ast.Stmt) bool {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, st); err != nil {
		return false
	}
	return strings.Join(strings.Fields(b.String()), " ") == "if fn == nil { return }"
}

// isDeferredCallTo matches `defer name()`.
func isDeferredCallTo(st ast.Stmt, name string) bool {
	d, ok := st.(*ast.DeferStmt)
	if !ok {
		return false
	}
	id, ok := d.Call.Fun.(*ast.Ident)
	return ok && id.Name == name && len(d.Call.Args) == 0
}

// printStmts renders statements one per line, position-independent.
func printStmts(t *testing.T, fset *token.FileSet, stmts []ast.Stmt) string {
	t.Helper()
	var out strings.Builder
	for _, st := range stmts {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, st); err != nil {
			t.Fatalf("print: %v", err)
		}
		out.WriteString(strings.TrimSpace(b.String()))
		out.WriteByte('\n')
	}
	return out.String()
}
