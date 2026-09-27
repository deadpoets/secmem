package secmemlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// escapeScan is the escape check over one borrowing closure. It runs in two
// phases:
//
//  1. Taint propagation. Starting from the borrowed []byte parameters, every
//     local declared inside the closure that is ever assigned a tainted value
//     (an alias, a conversion, a composite holding it, an element of it, a
//     closure capturing it, …) becomes tainted itself, to a fixpoint.
//  2. Reporting. Every place a tainted value can reach memory that outlives the
//     closure — assignment to an outer variable / field / element / pointee, a
//     channel send, a return, a goroutine, copy into an outer slice, append into
//     an outer slice, a string conversion, panic, or a known stdlib sink — is
//     reported once.
//
// "Tainted" is a property of VALUES: anything that aliases or was copied from
// the secret bytes. len(b), a comparison, and the result of a call the analyzer
// does not know are not tainted; that last one is the interprocedural limit.
type escapeScan struct {
	c       *checker
	acc     accessor
	taint   map[types.Object]bool
	aliases map[types.Object]bool // memo for aliasOfBorrowed
}

func (c *checker) checkCallbackEscapes(acc accessor) {
	if len(acc.params) == 0 {
		return
	}
	s := &escapeScan{
		c:       c,
		acc:     acc,
		taint:   make(map[types.Object]bool),
		aliases: make(map[types.Object]bool),
	}
	s.propagate()
	s.reportEscapes()
}

// --- phase 1: taint propagation ---

func (s *escapeScan) propagate() {
	for changed := true; changed; {
		changed = false
		ast.Inspect(s.acc.body, func(n ast.Node) bool {
			switch st := n.(type) {
			case *ast.AssignStmt:
				forPairs(st.Lhs, st.Rhs, func(l, r ast.Expr) {
					if s.tainted(r) && s.taintTarget(l) {
						changed = true
					}
				})
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, len(st.Names))
				for i, name := range st.Names {
					lhs[i] = name
				}
				forPairs(lhs, st.Values, func(l, r ast.Expr) {
					if s.tainted(r) && s.taintTarget(l) {
						changed = true
					}
				})
			case *ast.RangeStmt:
				if s.rangeTaint(st) {
					changed = true
				}
			case *ast.CallExpr:
				// copy(dst, tainted) makes dst's memory hold the secret.
				if builtinName(s.c.pass, st) == "copy" && len(st.Args) == 2 &&
					s.tainted(st.Args[1]) && s.taintTarget(st.Args[0]) {
					changed = true
				}
			}
			return true
		})
	}
}

// rangeTaint taints the variables a range statement over a tainted value
// declares. Over a slice, array or string the VALUE is the element (the key is
// an index and stays clean, as is the sole variable of a range over a slice).
// Over a channel or an iterator function the elements come through the FIRST
// variable — for c := range seq — so that one is tainted whenever it is the
// only one, and a second variable is tainted as an element too. The first of
// two variables of an iterator is tainted only when its type is a byte or can
// otherwise hold bytes (the c of a Seq2[byte, int], the k of a Seq2[[]byte, V]),
// so an index-like int key stays clean.
func (s *escapeScan) rangeTaint(st *ast.RangeStmt) bool {
	if !s.tainted(st.X) {
		return false
	}
	changed := false
	if st.Value != nil && s.taintTarget(st.Value) {
		changed = true
	}
	if st.Key == nil {
		return changed
	}
	switch types.Unalias(s.c.pass.TypesInfo.TypeOf(st.X)).Underlying().(type) {
	case *types.Chan:
		if s.taintTarget(st.Key) {
			changed = true
		}
	case *types.Signature:
		if (st.Value == nil || keyCarriesBytes(s.c.pass.TypesInfo.TypeOf(st.Key))) && s.taintTarget(st.Key) {
			changed = true
		}
	}
	return changed
}

// keyCarriesBytes reports whether the first of two range variables over an
// iterator can be the secret rather than an index: its type is a byte, or
// anything but a plain number or bool.
func keyCarriesBytes(t types.Type) bool {
	return isByteType(t) || resultCarriesBytes(t)
}

// forPairs pairs assignment sides: positionally when the counts match, or every
// left side with the single tuple-valued right side.
func forPairs(lhs, rhs []ast.Expr, fn func(l, r ast.Expr)) {
	switch {
	case len(lhs) == len(rhs):
		for i := range lhs {
			fn(lhs[i], rhs[i])
		}
	case len(rhs) == 1:
		for _, l := range lhs {
			fn(l, rhs[0])
		}
	}
}

// taintTarget marks the local a write lands in as tainted. Writes to the
// borrowed slice itself and to anything outside the closure are not taint
// (the latter is an escape, reported in phase 2). Returns true on a change.
func (s *escapeScan) taintTarget(target ast.Expr) bool {
	root := rootIdent(target)
	if root == nil {
		return false
	}
	obj := s.c.pass.TypesInfo.ObjectOf(root)
	if obj == nil || s.acc.params[obj] || s.taint[obj] || !withinNode(obj.Pos(), s.acc.node) {
		return false
	}
	s.taint[obj] = true
	return true
}

// --- taint of expressions ---

// tainted reports whether expr aliases, contains, or was derived from the
// borrowed bytes. Conversions to string and calls to known sinks are NOT
// tainted: they are reported where they happen, and tracking their result too
// would report the same leak twice.
func (s *escapeScan) tainted(expr ast.Expr) bool {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		obj := s.c.pass.TypesInfo.ObjectOf(e)
		return s.acc.params[obj] || s.taint[obj]
	case *ast.SliceExpr:
		return s.tainted(e.X)
	case *ast.IndexExpr:
		return s.tainted(e.X)
	case *ast.StarExpr:
		return s.tainted(e.X)
	case *ast.UnaryExpr:
		return s.tainted(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return false
		}
		return s.tainted(e.X) || s.tainted(e.Y)
	case *ast.TypeAssertExpr:
		return s.tainted(e.X)
	case *ast.SelectorExpr:
		if _, ok := s.c.pass.TypesInfo.Selections[e]; ok {
			return s.tainted(e.X) // field of / method on a tainted value
		}
		return false // package-qualified name
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if s.tainted(elt) {
				return true
			}
		}
		return false
	case *ast.KeyValueExpr:
		return s.tainted(e.Key) || s.tainted(e.Value)
	case *ast.FuncLit:
		return s.captures(e)
	case *ast.CallExpr:
		return s.callTainted(e)
	}
	return false
}

// captures reports whether a func literal's body refers to a tainted object.
func (s *escapeScan) captures(lit *ast.FuncLit) bool {
	found := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			obj := s.c.pass.TypesInfo.ObjectOf(id)
			if s.acc.params[obj] || s.taint[obj] {
				found = true
			}
		}
		return !found
	})
	return found
}

// callTainted decides the taint of a call's result.
func (s *escapeScan) callTainted(call *ast.CallExpr) bool {
	pass := s.c.pass
	// Conversion. string(b) is reported at the conversion; any other
	// conversion ([]byte(b), any(b), raw(b), unsafe.Pointer(&b[0])) just
	// carries the bytes along.
	if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) != 1 || isStringType(tv.Type) {
			return false
		}
		// uintptr(unsafe.Pointer(&b[0])) is the slice's ADDRESS, a number
		// that cannot be read through without unsafe again; it is not the
		// secret. (Anything still typed as a pointer stays tainted.)
		if isUintptr(tv.Type) && isUnsafePointer(pass.TypesInfo.TypeOf(call.Args[0])) {
			return false
		}
		return s.tainted(call.Args[0])
	}
	if name := builtinName(pass, call); name != "" {
		switch name {
		case "append":
			// Appending into an outer slice is reported at the call; the
			// result of appending into inner memory carries the bytes.
			if len(call.Args) == 0 || !s.inner(call.Args[0]) {
				return false
			}
			return s.anyTainted(call.Args)
		case "min", "max", "String", "SliceData", "StringData", "Slice":
			return s.anyTainted(call.Args)
		}
		return false
	}
	if _, reason := s.c.sinkFor(call); reason != "" {
		return false // reported at the call
	}
	if s.c.isAliasFunc(call) {
		return s.anyTainted(call.Args)
	}
	// A call through a tainted function value, or a method on a tainted
	// receiver (reflect.ValueOf(b).Interface(), h.bytes()), yields tainted
	// results unless the result is a plain number or bool.
	if s.tainted(call.Fun) {
		return resultCarriesBytes(pass.TypesInfo.TypeOf(call))
	}
	return false
}

func (s *escapeScan) anyTainted(exprs []ast.Expr) bool {
	for _, e := range exprs {
		if s.tainted(e) {
			return true
		}
	}
	return false
}

// resultCarriesBytes reports whether a value of type t could hold or reference
// secret bytes: anything but a plain number or bool.
func resultCarriesBytes(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if resultCarriesBytes(u.At(i).Type()) {
				return true
			}
		}
		return false
	case *types.Basic:
		return u.Info()&types.IsString != 0
	}
	return true
}

// --- inside / outside ---

// isLocal reports whether obj is declared inside the closure.
func (s *escapeScan) isLocal(obj types.Object) bool {
	return obj != nil && withinNode(obj.Pos(), s.acc.node)
}

// inner reports whether a write THROUGH the value of expr — copy or append
// into it as a slice, assignment through it as a pointer, a store into it as
// a map — lands in memory that stays inside the lease. The value is inside
// when:
//
//   - it is a borrowed slice — this closure's or another nested borrow's — or
//     a local alias of one: it lands in secure memory;
//   - it is a local slice / map / pointer whose every value is a fresh
//     allocation (make, new, a literal, the address of a local);
//   - it is a re-slice of a local array value, or the address of a local;
//   - it is a slice / pointer / map held in a field or element of a local
//     struct or array VALUE, and every value ever stored at that field or
//     element (by the local's initialiser, a literal, or an assignment to the
//     path) is itself fresh or a borrowed slice — so s.buf is inside after
//     s.buf = make([]byte, n) and outside after s.buf = callerSlice;
//   - it is a fresh value written in place, as in append([]byte(nil), b...).
//
// Everything else — an outer variable, a field of the enclosing receiver, a
// parameter of the enclosing function, a local whose provenance the index
// cannot see, a value reached through a pointer, slice or map whose contents
// are not tracked — is treated as outside.
func (s *escapeScan) inner(expr ast.Expr) bool {
	pass := s.c.pass
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		obj := pass.TypesInfo.ObjectOf(e)
		if s.acc.params[obj] || s.acc.otherBorrowed[obj] || s.aliasOfBorrowed(obj, 0) {
			return true
		}
		v, ok := obj.(*types.Var)
		if !ok || !s.isLocal(v) {
			return false
		}
		return s.c.defs.fresh(pass, v, s.isLocal)
	case *ast.SliceExpr:
		// x[i:j] is the same memory as x: an array's own storage, or the
		// backing array a slice / pointer-to-array refers to.
		if isArrayType(pass.TypesInfo.TypeOf(e.X)) {
			return s.innerStorage(e.X)
		}
		return s.inner(e.X)
	case *ast.UnaryExpr:
		return e.Op == token.AND && (s.innerStorage(e.X) || freshValue(pass, e, nil, s.isLocal))
	case *ast.SelectorExpr, *ast.IndexExpr:
		// The value stored in a field or element: the storage holding it must
		// be inside, and so must everything ever stored there.
		if !s.innerStorage(e) {
			return false
		}
		p, ok := pathOf(pass, e)
		return ok && !p.throughRef && s.pathInner(p)
	case *ast.StarExpr:
		// The value stored in a pointee (*pp as a slice): not tracked.
		return false
	}
	// Not a variable at all: a fresh value written in place, as in
	// append([]byte(nil), b...) or copy(make([]byte, n), b).
	return freshValue(pass, expr, nil, s.isLocal)
}

// innerStorage reports whether the storage location expr denotes as an
// lvalue — a variable, a field of a struct, an element of an array, slice or
// map, a pointee — is inside the lease. A local variable's own storage is; a
// field of a struct VALUE or an element of an array VALUE is wherever that
// value is; a field or element reached through a pointer, slice or map is
// wherever that reference points (see inner).
func (s *escapeScan) innerStorage(expr ast.Expr) bool {
	pass := s.c.pass
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		obj := pass.TypesInfo.ObjectOf(e)
		if s.acc.params[obj] || s.acc.otherBorrowed[obj] {
			return true
		}
		v, ok := obj.(*types.Var)
		return ok && s.isLocal(v)
	case *ast.SelectorExpr:
		sel, ok := pass.TypesInfo.Selections[e]
		if !ok || sel.Kind() != types.FieldVal {
			return false // a package-level variable, or not a field at all
		}
		if isPointerType(pass.TypesInfo.TypeOf(e.X)) {
			return s.inner(e.X) // the field lives in the pointee
		}
		if sel.Indirect() {
			return false // promoted through an embedded pointer: not followed
		}
		return s.innerStorage(e.X)
	case *ast.IndexExpr:
		t := types.Unalias(pass.TypesInfo.TypeOf(e.X))
		if _, ok := t.(*types.TypeParam); ok {
			return s.inner(e.X) // a type parameter's core type is a slice or array; both go through X
		}
		switch t.Underlying().(type) {
		case *types.Array:
			return s.innerStorage(e.X)
		case *types.Slice, *types.Map, *types.Pointer:
			return s.inner(e.X)
		}
		return false
	case *ast.StarExpr:
		return s.inner(e.X)
	}
	return false
}

// pathInner reports whether the reference (slice, pointer or map) stored at a
// field / element path of a local struct or array value is provably inside:
// the root is a local value written only by fresh-valued initialisers, every
// write to the path or to a prefix of it stores a fresh value at the path,
// and nothing has taken the value's address (after &s, a slice of it or of
// the array at the path — arr[:] is (&arr)[:] — or a pointer-receiver method
// call or method value on s, anything may write its fields).
func (s *escapeScan) pathInner(p accessPath) bool {
	if !s.isLocal(p.root) {
		return false
	}
	e := s.c.defs.vars[p.root]
	if e == nil || e.opaque != 0 || (len(e.defs) == 0 && !e.declared) {
		return false
	}
	for _, def := range e.defs {
		if def.tuple || !s.innerAt(def.expr, p, p.steps) {
			return false
		}
	}
	for _, pd := range s.c.defs.paths[p.root] {
		if !p.hasPrefix(pd.path) {
			continue // a write below the path (s.buf[0] = x) or beside it
		}
		if pd.opaque || !s.innerAt(pd.expr, p, p.steps[len(pd.path.steps):]) {
			return false
		}
	}
	return true
}

// innerAt reports whether the value expr, stored at some prefix of path,
// leaves what is reachable through the remaining steps inside: with no steps
// left, expr itself must be inside (fresh, or a borrowed slice); otherwise
// expr must be a composite literal whose element at the first step is itself
// innerAt the rest. An element the literal omits is a zero value — a nil
// slice, pointer or map — which is fresh.
func (s *escapeScan) innerAt(expr ast.Expr, path accessPath, steps []pathStep) bool {
	pass := s.c.pass
	expr = unparen(expr)
	if len(steps) == 0 {
		isSelf := func(e ast.Expr) bool {
			q, ok := pathOf(pass, e)
			return ok && q.equal(path)
		}
		if freshValue(pass, expr, isSelf, s.isLocal) {
			return true
		}
		if root := aliasRoot(expr); root != nil {
			o := pass.TypesInfo.ObjectOf(root)
			return s.acc.params[o] || s.acc.otherBorrowed[o] || s.aliasOfBorrowed(o, 0)
		}
		return false
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return false
	}
	if steps[0].field == "" {
		// An array / slice / map literal: every element.
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				elt = kv.Value
			}
			if !s.innerAt(elt, path, steps[1:]) {
				return false
			}
		}
		return true
	}
	st, ok := types.Unalias(pass.TypesInfo.TypeOf(lit)).Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == steps[0].field {
				return s.innerAt(kv.Value, path, steps[1:])
			}
			continue
		}
		if i < st.NumFields() && st.Field(i).Name() == steps[0].field {
			return s.innerAt(elt, path, steps[1:])
		}
	}
	return true // not mentioned: the zero value
}

// aliasOfBorrowed reports whether obj is a local bound once to (a slice or
// element of) a borrowed slice, so that writing through it writes secure
// memory.
func (s *escapeScan) aliasOfBorrowed(obj types.Object, depth int) bool {
	if depth > 8 {
		return false
	}
	if a, ok := s.aliases[obj]; ok {
		return a
	}
	v, ok := obj.(*types.Var)
	if !ok || !s.isLocal(v) {
		return false
	}
	def, ok := s.c.defs.singleDef(v)
	if !ok {
		return false
	}
	result := false
	if root := aliasRoot(def); root != nil {
		if o := s.c.pass.TypesInfo.ObjectOf(root); o != nil {
			result = s.acc.params[o] || s.acc.otherBorrowed[o] || s.aliasOfBorrowed(o, depth+1)
		}
	}
	s.aliases[obj] = result
	return result
}

// aliasRoot returns the identifier a slice/index/paren chain is rooted at —
// the shapes through which an assignment produces an alias of the same memory.
func aliasRoot(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.ParenExpr:
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// --- phase 2: reporting ---

func (s *escapeScan) reportEscapes() {
	var stack []ast.Node
	ast.Inspect(s.acc.body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch node := n.(type) {
		case *ast.CallExpr:
			s.checkCall(node)
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE {
				forPairs(node.Lhs, node.Rhs, func(l, r ast.Expr) {
					if s.tainted(r) {
						s.checkAssign(node, l)
					}
				})
			}
		case *ast.SendStmt:
			if s.tainted(node.Value) {
				s.c.report(node.Pos(), "borrowed secret bytes sent to a channel; they can outlive the closure")
			}
		case *ast.GoStmt:
			if node.Call != nil && (s.anyTainted(node.Call.Args) || s.tainted(node.Call.Fun)) {
				s.c.report(node.Pos(), "borrowed secret bytes handed to a goroutine; they can outlive the closure")
			}
		case *ast.ReturnStmt:
			// Only the closure's own return leaves the lease. A return inside a
			// nested func literal leaves that literal, which is caught where
			// the literal itself escapes.
			if !insideFuncLit(stack[:len(stack)-1]) && s.anyTainted(node.Results) {
				s.c.report(node.Pos(), "borrowed secret bytes returned from the closure; they can outlive it")
			}
		}
		return true
	})
}

func insideFuncLit(stack []ast.Node) bool {
	for _, n := range stack {
		if _, ok := n.(*ast.FuncLit); ok {
			return true
		}
	}
	return false
}

// checkCall handles the builtins and conversions with their own diagnostics
// (string, append, copy, panic) and the sink table.
func (s *escapeScan) checkCall(call *ast.CallExpr) {
	pass := s.c.pass
	if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) == 1 && isStringType(tv.Type) && s.tainted(call.Args[0]) {
			s.c.report(call.Pos(), "string() copies borrowed secret bytes into a heap string")
		}
		return
	}
	switch builtinName(pass, call) {
	case "append":
		if len(call.Args) >= 2 && !s.inner(call.Args[0]) && s.anyTainted(call.Args) {
			s.c.report(call.Pos(), "append() copies borrowed secret bytes into a slice outside the closure")
		}
		return
	case "copy":
		if len(call.Args) == 2 && s.tainted(call.Args[1]) && !s.inner(call.Args[0]) {
			s.c.report(call.Pos(), "copy() moves borrowed secret bytes out of the closure")
		}
		return
	case "panic":
		// The value is formatted into the runtime traceback and handed to
		// any recover() up the stack, both well outside the lease.
		if len(call.Args) == 1 && s.tainted(call.Args[0]) {
			s.c.report(call.Pos(), "panic() puts borrowed secret bytes in the traceback and in any recover()")
		}
		return
	}
	name, reason := s.c.sinkFor(call)
	if reason == "" {
		return
	}
	// A method sink fires on a tainted receiver too: ed25519.PrivateKey(b).Sign
	// hands the bytes to the FIPS cache exactly as ed25519.Sign(b, …) does.
	if s.anyTainted(call.Args) || s.taintedReceiver(call) {
		s.c.report(call.Pos(), fmt.Sprintf("borrowed secret bytes passed to %s; %s", name, reason))
	}
}

// taintedReceiver reports whether call is a method call whose receiver is
// tainted.
func (s *escapeScan) taintedReceiver(call *ast.CallExpr) bool {
	sel, ok := calleeSelector(call.Fun)
	if !ok {
		return false
	}
	if _, ok := s.c.pass.TypesInfo.Selections[sel]; !ok {
		return false
	}
	return s.tainted(sel.X)
}

// checkAssign reports an assignment of a tainted value to a target that can
// outlive the closure. Assigning to a local VARIABLE never escapes; writing
// into a field, element or pointee escapes unless that storage is provably
// inside (see innerStorage).
func (s *escapeScan) checkAssign(stmt *ast.AssignStmt, target ast.Expr) {
	var where string
	switch t := unparen(target).(type) {
	case *ast.Ident:
		if t.Name == "_" {
			return
		}
		// A local never escapes, and neither does a borrowed-slice variable
		// of this or an enclosing borrow: it is a lease variable itself and
		// dies with its closure.
		obj := s.c.pass.TypesInfo.ObjectOf(t)
		if obj == nil || s.isLocal(obj) || s.acc.params[obj] || s.acc.otherBorrowed[obj] {
			return
		}
		where = "a variable outside the closure"
	case *ast.StarExpr:
		if s.inner(t.X) {
			return
		}
		where = "a pointer target"
	case *ast.SelectorExpr:
		if s.innerStorage(t) {
			return
		}
		where = "a struct field"
		if _, ok := s.c.pass.TypesInfo.Selections[t]; !ok {
			where = "a variable outside the closure" // pkg.Var
		}
	case *ast.IndexExpr:
		if s.innerStorage(t) {
			return
		}
		where = "a map or slice element"
	default:
		return
	}
	s.c.report(stmt.Pos(), "borrowed secret bytes assigned to "+where+"; they can outlive the closure")
}

func isUintptr(t types.Type) bool {
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uintptr
}

func isUnsafePointer(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

// isByteType reports whether t is a byte (uint8, or a type defined on it).
func isByteType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uint8
}

func isPointerType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Pointer)
	return ok
}

func isArrayType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Array)
	return ok
}
