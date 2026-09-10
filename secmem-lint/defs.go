package secmemlint

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// defIndex is a per-pass index of where things are defined: every package-level
// function's declaration, and for every local variable the list of values ever
// assigned to it. The checks use it to answer two questions without a full
// dataflow analysis:
//
//   - "what does this identifier stand for?" — a closure variable passed to
//     WithBytes, a method value (l := buf.Len), an alias of a buffer
//     (b2 := buf), or a slot's arena (slot, _ := arena.Acquire()). Each is
//     resolved only through a SINGLE assignment; a variable written twice is
//     left unresolved rather than guessed at.
//   - "is this local's memory fresh?" — whether every value a local slice, map
//     or pointer ever holds is a fresh allocation, so that writing through it
//     cannot reach memory outside the closure.
type defIndex struct {
	funcDecls map[*types.Func]*ast.FuncDecl
	vars      map[*types.Var]*varDef
}

// varDef records the writes to one local variable.
type varDef struct {
	// defs are the direct assignments: x := e, var x = e, x = e, and the
	// tuple forms x, y := f() (where tuple is set and idx says which result).
	defs []valueDef
	// opaque counts writes the index cannot express as a value: range
	// variables, x++, op-assignment, and taking the variable's address (after
	// &x anything may write it).
	opaque int
	// declared is set when the variable comes from a var declaration with no
	// value (it starts at its zero value).
	declared bool
}

type valueDef struct {
	expr  ast.Expr
	tuple bool
	idx   int
}

func buildDefIndex(pass *analysis.Pass) *defIndex {
	d := &defIndex{
		funcDecls: make(map[*types.Func]*ast.FuncDecl),
		vars:      make(map[*types.Var]*varDef),
	}
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil {
				continue
			}
			if fn, ok := pass.TypesInfo.Defs[fd.Name].(*types.Func); ok {
				d.funcDecls[fn] = fd
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				d.recordAssign(pass, node)
			case *ast.ValueSpec:
				d.recordValueSpec(pass, node)
			case *ast.RangeStmt:
				d.recordOpaque(pass, node.Key)
				d.recordOpaque(pass, node.Value)
			case *ast.IncDecStmt:
				d.recordOpaque(pass, node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					d.recordOpaque(pass, node.X)
				}
			}
			return true
		})
	}
	return d
}

func (d *defIndex) varOf(pass *analysis.Pass, expr ast.Expr) *types.Var {
	id, ok := unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := pass.TypesInfo.ObjectOf(id).(*types.Var)
	return v
}

func (d *defIndex) entry(v *types.Var) *varDef {
	e := d.vars[v]
	if e == nil {
		e = &varDef{}
		d.vars[v] = e
	}
	return e
}

func (d *defIndex) recordAssign(pass *analysis.Pass, st *ast.AssignStmt) {
	if st.Tok != token.DEFINE && st.Tok != token.ASSIGN {
		// x += e and friends: a write, but not one that replaces the value.
		for _, l := range st.Lhs {
			d.recordOpaque(pass, l)
		}
		return
	}
	d.recordPairs(pass, st.Lhs, st.Rhs)
}

func (d *defIndex) recordValueSpec(pass *analysis.Pass, vs *ast.ValueSpec) {
	if len(vs.Values) == 0 {
		for _, name := range vs.Names {
			if v := d.varOf(pass, name); v != nil {
				d.entry(v).declared = true
			}
		}
		return
	}
	lhs := make([]ast.Expr, len(vs.Names))
	for i, name := range vs.Names {
		lhs[i] = name
	}
	d.recordPairs(pass, lhs, vs.Values)
}

func (d *defIndex) recordPairs(pass *analysis.Pass, lhs, rhs []ast.Expr) {
	switch {
	case len(lhs) == len(rhs):
		for i, l := range lhs {
			if v := d.varOf(pass, l); v != nil {
				e := d.entry(v)
				e.defs = append(e.defs, valueDef{expr: rhs[i]})
			}
		}
	case len(rhs) == 1:
		for i, l := range lhs {
			if v := d.varOf(pass, l); v != nil {
				e := d.entry(v)
				e.defs = append(e.defs, valueDef{expr: rhs[0], tuple: true, idx: i})
			}
		}
	default:
		for _, l := range lhs {
			d.recordOpaque(pass, l)
		}
	}
}

func (d *defIndex) recordOpaque(pass *analysis.Pass, expr ast.Expr) {
	if expr == nil {
		return
	}
	if v := d.varOf(pass, expr); v != nil {
		d.entry(v).opaque++
	}
}

// singleDef returns the one value ever assigned to v, if v is written exactly
// once by a plain (non-tuple) assignment or initialised declaration.
func (d *defIndex) singleDef(v *types.Var) (ast.Expr, bool) {
	e := d.vars[v]
	if e == nil || e.opaque != 0 || len(e.defs) != 1 || e.defs[0].tuple {
		return nil, false
	}
	return e.defs[0].expr, true
}

// singleTupleDef returns the call whose results initialise v, and v's index
// among them, when v is written exactly once as part of x, y := f().
func (d *defIndex) singleTupleDef(v *types.Var) (*ast.CallExpr, int, bool) {
	e := d.vars[v]
	if e == nil || e.opaque != 0 || len(e.defs) != 1 || !e.defs[0].tuple {
		return nil, 0, false
	}
	call, ok := unparen(e.defs[0].expr).(*ast.CallExpr)
	if !ok {
		return nil, 0, false
	}
	return call, e.defs[0].idx, true
}

// fresh reports whether every value v ever holds is memory allocated for it —
// make, new, a composite literal, the address of a local (per isLocal), nil,
// or a re-slice / append of itself — so that a write through v stays inside
// the function that declared it. A variable the index never saw a write to
// (a parameter, a range variable, an address-taken local) is not fresh.
func (d *defIndex) fresh(pass *analysis.Pass, v *types.Var, isLocal func(types.Object) bool) bool {
	e := d.vars[v]
	if e == nil || e.opaque != 0 {
		return false
	}
	if len(e.defs) == 0 {
		return e.declared
	}
	for _, def := range e.defs {
		if def.tuple || !freshValue(pass, def.expr, v, isLocal) {
			return false
		}
	}
	return true
}

func freshValue(pass *analysis.Pass, expr ast.Expr, self *types.Var, isLocal func(types.Object) bool) bool {
	switch e := unparen(expr).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.Ident:
		if e.Name == "nil" {
			return pass.TypesInfo.ObjectOf(e) == types.Universe.Lookup("nil")
		}
		return pass.TypesInfo.ObjectOf(e) == self
	case *ast.UnaryExpr:
		if e.Op != token.AND {
			return false
		}
		switch x := unparen(e.X).(type) {
		case *ast.CompositeLit:
			return true
		case *ast.Ident:
			obj := pass.TypesInfo.ObjectOf(x)
			return obj != nil && isLocal(obj)
		}
		return false
	case *ast.SliceExpr:
		return freshValue(pass, e.X, self, isLocal)
	case *ast.CallExpr:
		if builtinName(pass, e) == "make" || builtinName(pass, e) == "new" {
			return true
		}
		if builtinName(pass, e) == "append" && len(e.Args) > 0 {
			return freshValue(pass, e.Args[0], self, isLocal)
		}
		// A conversion of a literal ([]byte("..."), []byte(nil)) allocates.
		if tv, ok := pass.TypesInfo.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 {
			switch unparen(e.Args[0]).(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				return freshValue(pass, e.Args[0], self, isLocal)
			}
		}
	}
	return false
}

// builtinName returns the name of the builtin a call invokes ("append",
// "copy", "make", … and the unsafe package's "String", "SliceData", …), or "".
func builtinName(pass *analysis.Pass, call *ast.CallExpr) string {
	var id *ast.Ident
	switch fun := unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return ""
	}
	if b, ok := pass.TypesInfo.Uses[id].(*types.Builtin); ok {
		return b.Name()
	}
	return ""
}

func unparen(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}
