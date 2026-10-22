package secmemlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
)

// borrowWrapper marks a function or method that forwards a func parameter,
// unchanged, as the closure of a borrowing accessor (or of another wrapper)
// and uses it in no other way:
//
//	func withPassphrase(cfg *Config, fn func([]byte) error) error {
//		if cfg == nil || cfg.Passphrase == nil {
//			return ErrDestroyed
//		}
//		return cfg.Passphrase.WithBytesErr(fn)
//	}
//
// Whatever closure a caller passes for that parameter is borrowed exactly as
// if it had been passed to the accessor directly, so it is checked at the
// wrapper's call site. Params holds the indices of the forwarded parameters
// in the signature, receiver excluded. The fact is exported, so a wrapper is
// recognised in the packages that import it too.
type borrowWrapper struct{ Params []int }

func (*borrowWrapper) AFact() {}

func (w *borrowWrapper) String() string { return fmt.Sprintf("borrowWrapper%v", w.Params) }

// wrapperParam is one candidate: a borrow-shaped func parameter of a function
// declared in this package, and the calls it is passed to.
type wrapperParam struct {
	fn    *types.Func
	index int
	param *types.Var
	uses  []forwardUse
	bad   bool // used other than as a call argument or in a nil comparison
	done  bool
}

type forwardUse struct {
	call *ast.CallExpr
	arg  int
}

// findWrappers decides which functions of the package are borrowing wrappers
// and exports the fact for each. It is a least fixpoint: a parameter
// qualifies once every use of it is the closure argument of an accessor or of
// a wrapper already known, so a wrapper forwarding to another is found on a
// later round, and functions that only forward to each other never qualify.
func (c *checker) findWrappers() {
	var cands []*wrapperParam
	byVar := make(map[*types.Var]*wrapperParam)
	var bodies []*ast.BlockStmt
	for _, f := range c.pass.Files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn, ok := c.pass.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			sig := fn.Signature()
			found := false
			for i := 0; i < sig.Params().Len(); i++ {
				p := sig.Params().At(i)
				if (sig.Variadic() && i == sig.Params().Len()-1) || p.Name() == "" || p.Name() == "_" ||
					!isBorrowClosureType(p.Type()) {
					continue
				}
				wp := &wrapperParam{fn: fn, index: i, param: p}
				cands = append(cands, wp)
				byVar[p] = wp
				found = true
			}
			if found {
				bodies = append(bodies, fd.Body)
			}
		}
	}
	for _, body := range bodies {
		c.collectForwardUses(body, byVar)
	}
	for changed := true; changed; {
		changed = false
		for _, wp := range cands {
			if wp.done || wp.bad || len(wp.uses) == 0 || !c.allForwarded(wp.uses) {
				continue
			}
			wp.done, changed = true, true
			c.wrappers[wp.fn] = append(c.wrappers[wp.fn], wp.index)
			c.forwarded[wp.param] = true
		}
	}
	for fn, params := range c.wrappers {
		slices.Sort(params)
		c.pass.ExportObjectFact(fn, &borrowWrapper{Params: params})
	}
}

// collectForwardUses records, for every use of a candidate parameter in body,
// the call it is an argument of, and disqualifies the parameter on any other
// use but a comparison with nil.
func (c *checker) collectForwardUses(body *ast.BlockStmt, byVar map[*types.Var]*wrapperParam) {
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := c.pass.TypesInfo.Uses[id].(*types.Var)
		if !ok || byVar[v] == nil {
			return true
		}
		wp := byVar[v]
		child := ast.Node(id)
		i := len(stack) - 2
		for ; i >= 0; i-- {
			if _, ok := stack[i].(*ast.ParenExpr); !ok {
				break
			}
			child = stack[i]
		}
		if i < 0 {
			wp.bad = true
			return true
		}
		switch parent := stack[i].(type) {
		case *ast.CallExpr:
			for j, a := range parent.Args {
				if a == child {
					wp.uses = append(wp.uses, forwardUse{parent, j})
					return true
				}
			}
			wp.bad = true
		case *ast.BinaryExpr:
			other := parent.X
			if other == child {
				other = parent.Y
			}
			if (parent.Op != token.EQL && parent.Op != token.NEQ) || !c.pass.TypesInfo.Types[other].IsNil() {
				wp.bad = true
			}
		default:
			wp.bad = true
		}
		return true
	})
}

// allForwarded reports whether every use is the closure argument of a
// borrowing call.
func (c *checker) allForwarded(uses []forwardUse) bool {
	for _, u := range uses {
		mc, status := c.borrowCallee(u.call)
		if status != resolved {
			return false
		}
		if params := c.wrapperParams(mc.method); params != nil {
			if !slices.Contains(params, u.arg-mc.shift) {
				return false
			}
			continue
		}
		if arg := c.closureArgument(u.call); arg == nil || arg != u.call.Args[u.arg] {
			return false
		}
	}
	return true
}

// wrapperParams returns the forwarded parameter indices of fn when it is a
// borrowing wrapper — found in this package, or by a fact exported from the
// package that declares it — and nil otherwise.
func (c *checker) wrapperParams(fn *types.Func) []int {
	if fn == nil {
		return nil
	}
	fn = fn.Origin()
	if params, ok := c.wrappers[fn]; ok {
		return params
	}
	if fn.Pkg() == nil || fn.Pkg() == c.pass.Pkg {
		return nil
	}
	var w borrowWrapper
	if c.pass.ImportObjectFact(fn, &w) {
		return w.Params
	}
	return nil
}

// wrapperCall resolves a call of a borrowing wrapper: a function named
// directly, package-qualified or explicitly instantiated, or a method by any
// spelling methodCallOf understands. The receiver is dropped: the buffer the
// wrapper borrows is not its receiver, so its identity is unknown and the
// reentrancy check stays silent.
func (c *checker) wrapperCall(call *ast.CallExpr) (methodCall, bool) {
	mc := methodCall{method: c.funcObj(call.Fun)}
	if mc.method == nil {
		var ok bool
		if mc, ok = c.methodCallOf(call); !ok {
			return methodCall{}, false
		}
	}
	if c.wrapperParams(mc.method) == nil {
		return methodCall{}, false
	}
	mc.recv, mc.embedded = nil, nil
	return mc, true
}

// funcObj returns the function a non-method callee names: f, pkg.F, f[T] or
// pkg.F[T, U].
func (c *checker) funcObj(fun ast.Expr) *types.Func {
	switch f := unparen(fun).(type) {
	case *ast.Ident:
		fn, _ := c.pass.TypesInfo.Uses[f].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if _, ok := c.pass.TypesInfo.Selections[f]; ok {
			return nil
		}
		fn, _ := c.pass.TypesInfo.Uses[f.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr:
		return c.funcObj(f.X)
	case *ast.IndexListExpr:
		return c.funcObj(f.X)
	}
	return nil
}

// closureArgumentsOf returns the arguments carrying the borrowed closures of
// a resolved borrowing call: for a wrapper, the argument of every forwarded
// parameter; for an accessor, the first argument whose type is a func taking
// a []byte. It is empty when there is none.
func (c *checker) closureArgumentsOf(call *ast.CallExpr, mc methodCall) []ast.Expr {
	if params := c.wrapperParams(mc.method); params != nil {
		var args []ast.Expr
		for _, p := range params {
			if i := mc.shift + p; i < len(call.Args) {
				args = append(args, call.Args[i])
			}
		}
		return args
	}
	if arg := c.closureArgument(call); arg != nil {
		return []ast.Expr{arg}
	}
	return nil
}

// isForwardedParam reports whether arg names a parameter this package's
// wrapper analysis found to be forwarded (see borrowWrapper).
func (c *checker) isForwardedParam(arg ast.Expr) bool {
	id, ok := unparen(arg).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := c.pass.TypesInfo.Uses[id].(*types.Var)
	return ok && c.forwarded[v]
}
