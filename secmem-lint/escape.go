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
				if st.Value != nil && s.tainted(st.X) && s.taintTarget(st.Value) {
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

// inner reports whether a write through expr (copy into it, append into it,
// assignment to its element / field / pointee) stays inside the lease:
//
//   - it is rooted at a borrowed slice — this closure's or another
//     nested borrow's — or at a local alias of one: it lands in secure memory;
//   - it is rooted at a local struct or array VALUE;
//   - it is rooted at a local slice / map / pointer whose every value is a
//     fresh allocation (make, new, a literal, the address of a local).
//
// Everything else — an outer variable, a field of the enclosing receiver, a
// parameter of the enclosing function, a local whose provenance the index
// cannot see — is treated as outside.
func (s *escapeScan) inner(expr ast.Expr) bool {
	root := rootIdent(expr)
	if root == nil {
		// Not a variable at all: a fresh value written in place, as in
		// append([]byte(nil), b...) or copy(make([]byte, n), b).
		return freshValue(s.c.pass, expr, nil, s.isLocal)
	}
	obj := s.c.pass.TypesInfo.ObjectOf(root)
	if obj == nil {
		return false
	}
	if s.acc.params[obj] || s.acc.otherBorrowed[obj] || s.aliasOfBorrowed(obj, 0) {
		return true
	}
	v, ok := obj.(*types.Var)
	if !ok || !s.isLocal(v) {
		return false
	}
	switch types.Unalias(v.Type()).Underlying().(type) {
	case *types.Struct, *types.Array:
		return true
	}
	return s.c.defs.fresh(s.c.pass, v, s.isLocal)
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
	if reason != "" && s.anyTainted(call.Args) {
		s.c.report(call.Pos(), fmt.Sprintf("borrowed secret bytes passed to %s; %s", name, reason))
	}
}

// checkAssign reports an assignment of a tainted value to a target that can
// outlive the closure. Assigning to a local VARIABLE never escapes; writing
// through a local (element, field, pointee) escapes unless the local's memory
// is provably inside (see inner).
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
		if s.inner(t) {
			return
		}
		where = "a struct field"
	case *ast.IndexExpr:
		if s.inner(t) {
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
