package secmemlint

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// defIndex is a per-pass index of where things are defined: every package-level
// function's declaration, for every local variable the list of values ever
// assigned to it, and for every field / element path rooted at a variable
// (s.buf, arr[i], s.inner.dst) the list of values ever stored there. The checks
// use it to answer three questions without a full dataflow analysis:
//
//   - "what does this identifier stand for?" — a closure variable passed to
//     WithBytes, a method value (l := buf.Len), an alias of a buffer
//     (b2 := buf), or a slot's arena (slot, _ := arena.Acquire()). Each is
//     resolved only through a SINGLE assignment; a variable written twice is
//     left unresolved rather than guessed at.
//   - "is this local's memory fresh?" — whether every value a local slice, map
//     or pointer ever holds is a fresh allocation, so that writing through it
//     cannot reach memory outside the closure.
//   - "is the slice / pointer / map stored in this field or element of a local
//     struct or array value fresh?" — the same question one level down, so
//     that copy(s.buf, b) is inside when s.buf was made inside the closure and
//     outside when s.buf was set to a caller's slice.
type defIndex struct {
	funcDecls map[*types.Func]*ast.FuncDecl
	vars      map[*types.Var]*varDef
	// paths lists the writes to field / element paths rooted at each variable:
	// s.f = e, arr[i] = e, &s.f, s.f++, a slice of an array at the path
	// (s.arr[:] is (&s.arr)[:]), and the implicit &s of a pointer-receiver
	// method selected on s (a call s.m() or a method value s.m). The bare
	// variable's own writes are in vars.
	paths map[*types.Var][]pathDef
}

// varDef records the writes to one local variable.
type varDef struct {
	// defs are the direct assignments: x := e, var x = e, x = e, and the
	// tuple forms x, y := f() (where tuple is set and idx says which result).
	defs []valueDef
	// opaque counts writes the index cannot express as a value: range
	// variables, x++, op-assignment, taking the variable's address (after &x
	// anything may write it), slicing it when it is an array (arr[:] is
	// (&arr)[:], and a write through the slice is a write to arr), and
	// selecting a pointer-receiver method on it — a call x.m() or a method
	// value x.m — which takes &x implicitly.
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

// pathDef records one write to a field / element path: the value stored there,
// or an opaque write (address taken, a slice of an array at the path,
// op-assignment, tuple assignment, implicit & of a pointer-receiver method call
// or method value) after which the path may hold anything.
type pathDef struct {
	path   accessPath
	expr   ast.Expr // nil when opaque
	opaque bool
}

// accessPath is what a selector / index chain denotes: a root variable and the
// steps taken from it. Promoted fields are spelled out (e.f through embedded E
// is [E, f]) and an index names no particular element — all elements of an
// array, slice or map are pooled into one step, since which one a write hit
// is a runtime question.
type accessPath struct {
	root  *types.Var
	steps []pathStep
	// throughRef is set when the chain passes through a pointer (explicit *,
	// a pointer base, an embedded pointer field), a slice or a map on the way
	// to the final step. Values reached that way live in memory the path's
	// root does not own, so their provenance cannot be read off the root's
	// writes.
	throughRef bool
}

// pathStep is one selection: a field by name, or an element ("" — every
// element of an array, slice or map).
type pathStep struct{ field string }

// hasPrefix reports whether q's steps are a prefix of (or equal to) p's.
func (p accessPath) hasPrefix(q accessPath) bool {
	if p.root != q.root || len(q.steps) > len(p.steps) {
		return false
	}
	for i := range q.steps {
		if p.steps[i] != q.steps[i] {
			return false
		}
	}
	return true
}

func (p accessPath) equal(q accessPath) bool {
	return len(p.steps) == len(q.steps) && p.hasPrefix(q)
}

// pathOf decomposes a selector / index / deref chain rooted at a variable into
// an accessPath. It reports false for anything not rooted at a variable (a
// package-qualified name, a call result) and for a bare identifier, which is
// a variable rather than a path into one.
func pathOf(pass *analysis.Pass, expr ast.Expr) (accessPath, bool) {
	var rev []pathStep // steps, innermost last
	through := false
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.SelectorExpr:
			sel, ok := pass.TypesInfo.Selections[e]
			if !ok || sel.Kind() != types.FieldVal {
				return accessPath{}, false
			}
			if sel.Indirect() {
				through = true
			}
			// Spell out the promotion: sel.Index() is the field index at each
			// embedding level, innermost last.
			names := fieldNames(pass.TypesInfo.TypeOf(e.X), sel.Index())
			for i := len(names) - 1; i >= 0; i-- {
				rev = append(rev, pathStep{names[i]})
			}
			expr = e.X
		case *ast.IndexExpr:
			switch types.Unalias(pass.TypesInfo.TypeOf(e.X)).Underlying().(type) {
			case *types.Array:
			default:
				through = true // a slice, map or pointer-to-array element
			}
			rev = append(rev, pathStep{})
			expr = e.X
		case *ast.StarExpr:
			through = true
			expr = e.X
		case *ast.Ident:
			v, ok := pass.TypesInfo.ObjectOf(e).(*types.Var)
			if !ok || len(rev) == 0 {
				return accessPath{}, false
			}
			steps := make([]pathStep, len(rev))
			for i, st := range rev {
				steps[len(rev)-1-i] = st
			}
			return accessPath{root: v, steps: steps, throughRef: through}, true
		default:
			return accessPath{}, false
		}
	}
}

// fieldNames returns the names of the fields a selection's index path walks
// through, starting from a value of type t.
func fieldNames(t types.Type, index []int) []string {
	names := make([]string, 0, len(index))
	for _, i := range index {
		t = types.Unalias(t)
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			return names
		}
		f := st.Field(i)
		names = append(names, f.Name())
		t = f.Type()
	}
	return names
}

func buildDefIndex(pass *analysis.Pass) *defIndex {
	d := &defIndex{
		funcDecls: make(map[*types.Func]*ast.FuncDecl),
		vars:      make(map[*types.Var]*varDef),
		paths:     make(map[*types.Var][]pathDef),
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
			case *ast.SliceExpr:
				// Slicing an addressable array takes its address implicitly:
				// arr[:] is (&arr)[:], and whoever holds the slice can write
				// arr's elements. Slicing a slice, string or pointer-to-array
				// aliases memory the operand already referred to, not a
				// local's own storage, so only the array case is recorded.
				if isArrayType(pass.TypesInfo.TypeOf(node.X)) {
					d.recordOpaque(pass, node.X)
				}
			case *ast.SelectorExpr:
				d.recordImplicitAddr(pass, node)
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
			} else if p, ok := pathOf(pass, l); ok {
				d.paths[p.root] = append(d.paths[p.root], pathDef{path: p, expr: rhs[i]})
			}
		}
	case len(rhs) == 1:
		for i, l := range lhs {
			if v := d.varOf(pass, l); v != nil {
				e := d.entry(v)
				e.defs = append(e.defs, valueDef{expr: rhs[0], tuple: true, idx: i})
			} else {
				d.recordOpaque(pass, l) // a path assigned one result of a tuple
			}
		}
	default:
		for _, l := range lhs {
			d.recordOpaque(pass, l)
		}
	}
}

// recordOpaque marks a write the index cannot express as a value: to the
// variable expr names, or to the field / element path it denotes.
func (d *defIndex) recordOpaque(pass *analysis.Pass, expr ast.Expr) {
	if expr == nil {
		return
	}
	if v := d.varOf(pass, expr); v != nil {
		d.entry(v).opaque++
		return
	}
	if p, ok := pathOf(pass, expr); ok {
		d.paths[p.root] = append(d.paths[p.root], pathDef{path: p, opaque: true})
	}
}

// recordImplicitAddr marks the receiver of a pointer-receiver method selected
// on an addressable VALUE as opaque: x.m with m declared on *T and x of type T
// is (&x).m — whether it is called on the spot (x.m()) or taken as a method
// value (f := x.m; apply(x.m, …)) that runs later — and m may store anything
// into x's fields whenever it runs. A receiver that is already a pointer (or
// reached through an embedded pointer) is not affected — the method writes
// through that pointer, not into a local's storage.
func (d *defIndex) recordImplicitAddr(pass *analysis.Pass, sel *ast.SelectorExpr) {
	selection, ok := pass.TypesInfo.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return
	}
	sig, ok := selection.Obj().Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return
	}
	if _, ptrRecv := types.Unalias(sig.Recv().Type()).(*types.Pointer); !ptrRecv {
		return
	}
	// Walk the embedded path: the method's actual receiver is the innermost
	// field. If that is a pointer, no address is taken of anything local.
	t := pass.TypesInfo.TypeOf(sel.X)
	index := selection.Index()
	for _, i := range index[:len(index)-1] {
		t = types.Unalias(t)
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			return
		}
		t = st.Field(i).Type()
	}
	if _, isPtr := types.Unalias(t).Underlying().(*types.Pointer); isPtr {
		return
	}
	d.recordOpaque(pass, sel.X)
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
// (a parameter, a range variable, an address-taken or sliced local) is not
// fresh.
func (d *defIndex) fresh(pass *analysis.Pass, v *types.Var, isLocal func(types.Object) bool) bool {
	e := d.vars[v]
	if e == nil || e.opaque != 0 {
		return false
	}
	if len(e.defs) == 0 {
		return e.declared
	}
	isSelf := func(expr ast.Expr) bool {
		id, ok := unparen(expr).(*ast.Ident)
		return ok && pass.TypesInfo.ObjectOf(id) == v
	}
	for _, def := range e.defs {
		if def.tuple || !freshValue(pass, def.expr, isSelf, isLocal) {
			return false
		}
	}
	return true
}

// freshValue reports whether expr evaluates to memory allocated on the spot:
// make, new, a composite literal or its address, the address of a local (per
// isLocal), nil, a conversion of a literal, or a re-slice / append of the
// location being defined (per isSelf, which may be nil).
func freshValue(pass *analysis.Pass, expr ast.Expr, isSelf func(ast.Expr) bool, isLocal func(types.Object) bool) bool {
	switch e := unparen(expr).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.Ident:
		if e.Name == "nil" {
			return pass.TypesInfo.ObjectOf(e) == types.Universe.Lookup("nil")
		}
		return isSelf != nil && isSelf(e)
	case *ast.SelectorExpr, *ast.IndexExpr:
		return isSelf != nil && isSelf(e)
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
		return freshValue(pass, e.X, isSelf, isLocal)
	case *ast.CallExpr:
		if builtinName(pass, e) == "make" || builtinName(pass, e) == "new" {
			return true
		}
		if builtinName(pass, e) == "append" && len(e.Args) > 0 {
			return freshValue(pass, e.Args[0], isSelf, isLocal)
		}
		// A conversion of a literal ([]byte("..."), []byte(nil)) allocates.
		if tv, ok := pass.TypesInfo.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 {
			switch unparen(e.Args[0]).(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				return freshValue(pass, e.Args[0], isSelf, isLocal)
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

// calleeSelector returns the selector a call's function is spelled as, looking
// through parentheses and an explicit instantiation (slices.Clip[[]byte](b)).
func calleeSelector(fun ast.Expr) (*ast.SelectorExpr, bool) {
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
		case *ast.IndexExpr:
			fun = f.X
		case *ast.IndexListExpr:
			fun = f.X
		case *ast.SelectorExpr:
			return f, true
		default:
			return nil, false
		}
	}
}
