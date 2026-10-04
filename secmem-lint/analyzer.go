package secmemlint

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	secmemPkg  = "github.com/deadpoets/secmem"
	cryptoPkg  = "github.com/deadpoets/secmem/secmem-crypto"
	diagPrefix = "secmem-lint: "
)

// Analyzer is the secmem-lint analysis pass. It is exported so it can be driven
// by cmd/secmem-lint (singlechecker, for `go vet -vettool`) or embedded as a
// golangci-lint module plugin.
var Analyzer = &analysis.Analyzer{ //nolint:gochecknoglobals // go/analysis convention: the analyzer is an exported package-level var.
	Name:     "secmemlint",
	Doc:      "flags secret material escaping a secmem borrowing closure",
	URL:      "https://github.com/deadpoets/secmem/tree/main/secmem-lint",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// checker carries the per-pass state shared by every check.
type checker struct {
	pass     *analysis.Pass
	sup      *suppressor
	defs     *defIndex
	reported map[reportKey]bool
}

type reportKey struct {
	pos token.Pos
	msg string
}

func run(pass *analysis.Pass) (any, error) {
	insp, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, errors.New("secmem-lint: missing inspect analyzer result")
	}
	c := &checker{
		pass:     pass,
		sup:      newSuppressor(pass),
		defs:     buildDefIndex(pass),
		reported: make(map[reportKey]bool),
	}

	insp.WithStack([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		call := n.(*ast.CallExpr)
		acc, status := c.borrowAccessor(call, stack)
		switch status {
		case notBorrow:
			return true
		case unresolvedClosure:
			// The closure is something the analyzer cannot see into — a value
			// returned by a call, a method value, a field. Silence would let a
			// project believe it is covered; strict mode says so instead.
			if strict {
				c.report(acc.closureArg.Pos(),
					"borrowed closure is not a function literal and cannot be checked; pass a func literal, a local variable assigned one, or a function declared in this package")
			}
			return true
		case unresolvedCallee:
			// The call goes through a variable that holds a borrowing method
			// value on some assignments and something else on others, so
			// whether the closure is borrowed at all is a runtime question.
			// The literal is not checked; strict mode says so.
			if strict {
				c.report(acc.closureArg.Pos(),
					"closure passed through a variable that is sometimes a borrowing method value and sometimes not; it cannot be checked — bind the accessor once or call it directly")
			}
			return true
		}
		c.checkCallbackEscapes(acc)
		c.checkReentrancy(acc)
		return true
	})
	if strict {
		checkSecretNamedStrings(pass, insp, c.sup)
		checkMissingDestroy(pass, insp, c.sup)
	}
	return nil, nil //nolint:nilnil // go/analysis Run returns (nil result, nil error) when it has no Result to publish.
}

// report emits a finding with the shared secmem-lint prefix, unless the line is
// suppressed or the identical finding was already emitted. The same closure
// body can be reached from several call sites (a named function or a closure
// variable passed to WithBytes twice), and one finding per line is the
// contract.
func (c *checker) report(pos token.Pos, msg string) {
	if c.sup.suppressed(c.pass, pos) {
		return
	}
	key := reportKey{pos, msg}
	if c.reported[key] {
		return
	}
	c.reported[key] = true
	c.pass.Report(analysis.Diagnostic{Pos: pos, Message: diagPrefix + msg})
}

// accessor is a recognized secmem borrowing-closure call —
// recv.Method(func(p []byte) { ... }) — with the closure resolved to a body.
//
// Receiver and parameters are identified by types.Object rather than by name
// or AST shape. Names are the wrong key twice over: a receiver written as a
// field selector (s.buf) is not an identifier at all, and a borrowed
// parameter's name can be shadowed by an unrelated variable that matches.
type accessor struct {
	call       *ast.CallExpr
	method     *types.Func
	recvExpr   ast.Expr       // the receiver expression as written; nil if undecidable
	recv       []types.Object // receiver identity chain, nil if undecidable
	closureArg ast.Expr       // the argument the closure was resolved from
	node       ast.Node       // *ast.FuncLit or *ast.FuncDecl: the closure's extent
	body       *ast.BlockStmt
	params     map[types.Object]bool // its []byte parameters (the borrowed slices)
	// otherBorrowed are the []byte parameters of the other borrowing closures
	// this one is syntactically nested inside or contains. Each is secure
	// memory: writing into one is the documented decrypt-into pattern, not an
	// escape, whichever way round the two borrows nest.
	otherBorrowed map[types.Object]bool
}

type accessorStatus int

const (
	notBorrow accessorStatus = iota
	resolved
	unresolvedClosure
	unresolvedCallee
)

// methodCall is a call resolved to the method it invokes: the receiver
// expression as written (nil when the call goes through a variable bound to
// method values of more than one receiver) and the embedded fields the method
// was promoted through, so that e.Len() and e.SecureBuffer.Len() — the same
// buffer, spelled with and without the promotion — get the same identity.
type methodCall struct {
	method   *types.Func
	recv     ast.Expr
	embedded []types.Object
}

// receiverKey builds the identity chain of a resolved method call's receiver:
// the chain of the receiver expression (see checker.receiverKey) extended by
// the embedded fields the method was promoted through.
func (c *checker) receiverKeyOf(mc methodCall) ([]types.Object, bool) {
	if mc.recv == nil {
		return nil, false
	}
	base, ok := c.receiverKey(mc.recv, 0)
	if !ok {
		return nil, false
	}
	key := make([]types.Object, 0, len(base)+len(mc.embedded))
	key = append(key, base...)
	return append(key, mc.embedded...), true
}

// borrowAccessor reports whether call is a secmem borrowing accessor and, if so,
// resolves the closure it borrows to. Matching is type-aware: the method must be
// declared on a secmem (or secmem-crypto) type, or on an interface whose method
// has the borrowing shape, so an unrelated WithBytes on some other library's
// concrete type is not flagged.
func (c *checker) borrowAccessor(call *ast.CallExpr, stack []ast.Node) (accessor, accessorStatus) {
	mc, status := c.borrowCallee(call)
	if status == notBorrow {
		return accessor{}, notBorrow
	}
	arg := c.closureArgument(call)
	if arg == nil {
		return accessor{}, notBorrow
	}
	acc := accessor{call: call, method: mc.method, recvExpr: mc.recv, closureArg: arg}
	if status == unresolvedCallee {
		return acc, unresolvedCallee
	}
	acc.node, acc.body = c.resolveClosure(arg)
	if acc.body == nil {
		return acc, unresolvedClosure
	}
	// The parameters are decided on the closure's type AT THE CALL, which for
	// a generic function passed by name (func leak[T ~[]byte](b T)) is the
	// instantiated signature; the declared one says only T.
	acc.params = c.byteSliceParams(closureType(acc.node), c.pass.TypesInfo.TypeOf(arg))
	acc.recv, _ = c.receiverKeyOf(mc)
	acc.otherBorrowed = make(map[types.Object]bool)
	for _, anc := range stack {
		if pc, ok := anc.(*ast.CallExpr); ok && pc != call {
			c.addBorrowedParams(pc, acc.otherBorrowed)
		}
	}
	ast.Inspect(acc.body, func(n ast.Node) bool {
		if pc, ok := n.(*ast.CallExpr); ok {
			c.addBorrowedParams(pc, acc.otherBorrowed)
		}
		return true
	})
	return acc, resolved
}

// addBorrowedParams adds the []byte parameters of the func literal a borrowing
// call is passed (if call is one) to set.
func (c *checker) addBorrowedParams(call *ast.CallExpr, set map[types.Object]bool) {
	if _, status := c.borrowCallee(call); status != resolved {
		return
	}
	for _, a := range call.Args {
		if lit, ok := a.(*ast.FuncLit); ok {
			for p := range c.byteSliceParams(lit.Type, c.pass.TypesInfo.TypeOf(lit)) {
				set[p] = true
			}
		}
	}
}

// borrowCallee resolves the method a call invokes and the receiver expression
// it is invoked on, when that method is a borrowing accessor. The spellings
// understood are the direct recv.WithBytes(...), the method expression
// (*secmem.SecureBuffer).WithBytes(recv, ...), and a call through a local
// variable holding the method value (f := recv.WithBytes; f(...)) — bound once
// to one receiver, or several times to borrowing accessors of several
// receivers (the closure is still borrowed and is checked; only the receiver's
// identity is unknown). A variable that is a borrowing method value on some
// assignments and something else on others is unresolvedCallee.
func (c *checker) borrowCallee(call *ast.CallExpr) (methodCall, accessorStatus) {
	if id, ok := unparen(call.Fun).(*ast.Ident); ok {
		return c.borrowCalleeVar(call, id)
	}
	mc, ok := c.methodCallOf(call)
	if !ok || !isBorrowMethod(mc.method) {
		return methodCall{}, notBorrow
	}
	return mc, resolved
}

// borrowCalleeVar resolves a call through a variable: every value the variable
// is ever assigned must be a borrowing method value.
func (c *checker) borrowCalleeVar(call *ast.CallExpr, id *ast.Ident) (methodCall, accessorStatus) {
	v, ok := c.pass.TypesInfo.Uses[id].(*types.Var)
	if !ok {
		return methodCall{}, notBorrow
	}
	e := c.defs.vars[v]
	if e == nil || len(e.defs) == 0 {
		return methodCall{}, notBorrow
	}
	var first methodCall
	borrowing, total := 0, 0
	for _, def := range e.defs {
		total++
		if def.tuple {
			continue
		}
		mc, ok := c.methodCallOf(&ast.CallExpr{Fun: def.expr, Args: call.Args})
		if !ok || !isBorrowMethod(mc.method) {
			continue
		}
		if borrowing == 0 {
			first = mc
		}
		borrowing++
	}
	switch {
	case borrowing == 0:
		return methodCall{}, notBorrow
	case borrowing < total || e.opaque != 0:
		return methodCall{}, unresolvedCallee
	case borrowing > 1:
		first.recv, first.embedded = nil, nil // several receivers: identity undecidable
	}
	return first, resolved
}

// methodCallOf resolves the method a call invokes, when its function is spelled
// as a method value (recv.M, possibly via an identifier bound once to one) or a
// method expression ((*T).M with the receiver as the first argument).
func (c *checker) methodCallOf(call *ast.CallExpr) (methodCall, bool) {
	sel, ok := c.methodSelector(call.Fun)
	if !ok {
		return methodCall{}, false
	}
	selection, ok := c.pass.TypesInfo.Selections[sel]
	if !ok {
		return methodCall{}, false
	}
	m, ok := selection.Obj().(*types.Func)
	if !ok {
		return methodCall{}, false
	}
	var recv ast.Expr
	switch selection.Kind() {
	case types.MethodVal:
		recv = sel.X
	case types.MethodExpr:
		if len(call.Args) == 0 {
			return methodCall{}, false
		}
		recv = call.Args[0]
	default:
		return methodCall{}, false
	}
	index := selection.Index()
	return methodCall{
		method:   m,
		recv:     recv,
		embedded: embeddedFields(c.pass.TypesInfo.TypeOf(recv), index[:len(index)-1]),
	}, true
}

// embeddedFields returns the field objects a promoted selection walks through,
// starting from a value of type t (the receiver as written).
func embeddedFields(t types.Type, index []int) []types.Object {
	if len(index) == 0 || t == nil {
		return nil
	}
	fields := make([]types.Object, 0, len(index))
	for _, i := range index {
		t = types.Unalias(t)
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			return fields
		}
		f := st.Field(i)
		fields = append(fields, f)
		t = f.Type()
	}
	return fields
}

// methodSelector returns the selector expression a call's function ultimately
// names: the selector itself, or — for an identifier bound once to a method
// value — the selector it was bound to.
func (c *checker) methodSelector(fun ast.Expr) (*ast.SelectorExpr, bool) {
	switch f := unparen(fun).(type) {
	case *ast.SelectorExpr:
		return f, true
	case *ast.Ident:
		v, ok := c.pass.TypesInfo.Uses[f].(*types.Var)
		if !ok {
			return nil, false
		}
		def, ok := c.defs.singleDef(v)
		if !ok {
			return nil, false
		}
		sel, ok := unparen(def).(*ast.SelectorExpr)
		return sel, ok
	}
	return nil, false
}

// borrowMethods names, per package, the methods that lend their receiver's
// bytes to a closure for the duration of the call.
var borrowMethods = map[string]map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	secmemPkg: {"WithBytes": true, "WithBytesErr": true},
	cryptoPkg: {"WithScalar": true, "WithSeed": true, "WithDER": true},
}

// isBorrowMethod reports whether m is a borrowing accessor: one of the known
// methods on a secmem / secmem-crypto type, or — the interface heuristic — a
// method of the same name and shape (one func parameter taking a []byte)
// declared on an interface, since a *secmem.SecureBuffer held behind an
// interface is still the same buffer.
func isBorrowMethod(m *types.Func) bool {
	if m.Pkg() == nil {
		return false
	}
	if names, ok := borrowMethods[m.Pkg().Path()]; ok {
		return names[m.Name()]
	}
	if !borrowMethods[secmemPkg][m.Name()] && !borrowMethods[cryptoPkg][m.Name()] {
		return false
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || !types.IsInterface(sig.Recv().Type()) {
		return false
	}
	return sig.Params().Len() == 1 && isBorrowClosureType(sig.Params().At(0).Type())
}

// isBorrowClosureType reports whether t is a func type with a []byte parameter.
func isBorrowClosureType(t types.Type) bool {
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if isByteSliceType(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// closureArgument returns the argument carrying the borrowing closure: the
// first one whose static type is a func taking a []byte.
func (c *checker) closureArgument(call *ast.CallExpr) ast.Expr {
	for _, arg := range call.Args {
		if t := c.pass.TypesInfo.TypeOf(arg); t != nil && isBorrowClosureType(t) {
			return arg
		}
	}
	return nil
}

// resolveClosure finds the function body a closure argument stands for:
//
//   - a func literal;
//   - an identifier bound exactly once (fn := func(b []byte) {...}) to a func
//     literal;
//   - an identifier naming a function declared at package level in the
//     package under analysis, bare (leak) or explicitly instantiated
//     (leak[[]byte]).
//
// Anything else — a call result, a method value, a field, a variable assigned
// more than once, a function from another package — resolves to nil.
func (c *checker) resolveClosure(arg ast.Expr) (ast.Node, *ast.BlockStmt) {
	switch e := unparen(arg).(type) {
	case *ast.FuncLit:
		return e, e.Body
	case *ast.Ident:
		switch obj := c.pass.TypesInfo.Uses[e].(type) {
		case *types.Var:
			def, ok := c.defs.singleDef(obj)
			if !ok {
				return nil, nil
			}
			if lit, ok := unparen(def).(*ast.FuncLit); ok {
				return lit, lit.Body
			}
		case *types.Func:
			return c.funcDeclOf(obj)
		}
	case *ast.IndexExpr:
		return c.resolveInstantiation(e.X)
	case *ast.IndexListExpr:
		return c.resolveInstantiation(e.X)
	}
	return nil, nil
}

// resolveInstantiation resolves the function an explicit instantiation
// (leak[[]byte], leak[K, V]) names to its declaration in this package. Uses
// records the generic function itself for the instantiated identifier, which
// is the key funcDecls is built on; the instantiated signature is read off the
// argument's type where the parameters are decided (see byteSliceParams).
func (c *checker) resolveInstantiation(fun ast.Expr) (ast.Node, *ast.BlockStmt) {
	id, ok := unparen(fun).(*ast.Ident)
	if !ok {
		return nil, nil
	}
	fn, ok := c.pass.TypesInfo.Uses[id].(*types.Func)
	if !ok {
		return nil, nil
	}
	return c.funcDeclOf(fn)
}

// funcDeclOf returns the declaration of a function in the package under
// analysis, when it has a body.
func (c *checker) funcDeclOf(fn *types.Func) (ast.Node, *ast.BlockStmt) {
	if decl := c.defs.funcDecls[fn]; decl != nil && decl.Body != nil {
		return decl, decl.Body
	}
	return nil, nil
}

func closureType(node ast.Node) *ast.FuncType {
	switch n := node.(type) {
	case *ast.FuncLit:
		return n.Type
	case *ast.FuncDecl:
		return n.Type
	}
	return nil
}

// receiverKey builds a comparison key for a receiver expression: the chain of
// objects from the root identifier through any field selections, so buf and
// s.buf and s.inner.buf each get a key that can be compared for identity. A
// local bound exactly once to another receiver expression (b2 := buf) resolves
// to that expression's key.
//
// It reports false for shapes whose identity cannot be decided statically —
// index expressions, calls, type assertions. bufs[i] and bufs[j] are written
// alike and need not be the same buffer, and getBuf() twice need not return the
// same one, so treating them as equal would be a false positive on a linter
// whose findings block a build.
func (c *checker) receiverKey(expr ast.Expr, depth int) ([]types.Object, bool) {
	const maxAliasDepth = 8
	switch e := expr.(type) {
	case *ast.Ident:
		obj := c.pass.TypesInfo.ObjectOf(e)
		if obj == nil {
			return nil, false
		}
		if v, ok := obj.(*types.Var); ok && depth < maxAliasDepth {
			if def, ok := c.defs.singleDef(v); ok && isReceiverShaped(def) {
				return c.receiverKey(def, depth+1)
			}
		}
		return []types.Object{obj}, true

	case *ast.ParenExpr:
		return c.receiverKey(e.X, depth)

	case *ast.StarExpr:
		// (*p).WithBytes(...) names the same buffer as p.WithBytes(...).
		return c.receiverKey(e.X, depth)

	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return c.receiverKey(e.X, depth)
		}

	case *ast.SelectorExpr:
		base, ok := c.receiverKey(e.X, depth)
		if !ok {
			return nil, false
		}
		field := c.pass.TypesInfo.ObjectOf(e.Sel)
		if field == nil {
			return nil, false
		}
		key := make([]types.Object, 0, len(base)+1)
		key = append(key, base...)
		return append(key, field), true
	}
	return nil, false
}

// isReceiverShaped reports whether expr is a plain name / field / deref chain —
// the shapes an alias assignment can be followed through.
func isReceiverShaped(expr ast.Expr) bool {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		return e.Name != "nil"
	case *ast.StarExpr:
		return isReceiverShaped(e.X)
	case *ast.UnaryExpr:
		return e.Op == token.AND && isReceiverShaped(e.X)
	case *ast.SelectorExpr:
		return isReceiverShaped(e.X)
	}
	return false
}

// sameReceiver reports whether two receiver keys name the same buffer.
func sameReceiver(a, b []types.Object) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// byteSliceParams returns the function's []byte parameters — the borrowed
// slices whose escape the checks track. Each declared parameter is decided on
// the corresponding parameter of sig, the closure's type where it is passed:
// for a generic function that is the instantiated signature, in which a
// parameter declared as T ~[]byte is a []byte. Without sig (or past its end)
// the declared type is used, resolved so that a parameter declared through an
// alias (type raw = []byte) is still tracked.
func (c *checker) byteSliceParams(ft *ast.FuncType, closureType types.Type) map[types.Object]bool {
	objs := make(map[types.Object]bool)
	if ft == nil || ft.Params == nil {
		return objs
	}
	var params *types.Tuple
	if closureType != nil {
		if sig, ok := types.Unalias(closureType).Underlying().(*types.Signature); ok {
			params = sig.Params()
		}
	}
	idx := 0
	for _, field := range ft.Params.List {
		n := len(field.Names)
		if n == 0 {
			n = 1 // an unnamed parameter still occupies a position
		}
		t := c.pass.TypesInfo.TypeOf(field.Type)
		if params != nil && idx < params.Len() {
			t = params.At(idx).Type()
		}
		idx += n
		if !isByteSliceType(t) {
			continue
		}
		for _, name := range field.Names {
			if name.Name == "_" {
				continue
			}
			if obj := c.pass.TypesInfo.ObjectOf(name); obj != nil {
				objs[obj] = true
			}
		}
	}
	return objs
}

func isByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	s, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := s.Elem().Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uint8
}

// namedTypeKey returns "import/path.TypeName" for a (pointer to a) named or
// aliased type from another package, or "" for anything else.
func namedTypeKey(t types.Type) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	return named.Obj().Pkg().Path() + "." + named.Obj().Name()
}

// --- suppression: //nolint:secmem-lint (or a bare //nolint) on the finding line ---

type suppressor struct {
	lines map[string]bool
}

func newSuppressor(pass *analysis.Pass) *suppressor {
	s := &suppressor{lines: make(map[string]bool)}
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if nolintApplies(c.Text) {
					p := pass.Fset.Position(c.Pos())
					s.lines[lineKey(p.Filename, p.Line)] = true
				}
			}
		}
	}
	return s
}

func (s *suppressor) suppressed(pass *analysis.Pass, pos token.Pos) bool {
	p := pass.Fset.Position(pos)
	return s.lines[lineKey(p.Filename, p.Line)]
}

func lineKey(file string, line int) string {
	return file + ":" + strconv.Itoa(line)
}

// nolintApplies reports whether a //nolint directive covers secmem-lint: a bare
// //nolint, or //nolint:<list> where the list contains secmem-lint or all
// (golangci-lint's spelling of "every linter", honoured here so a line one
// tool has excused is not failed by the other).
func nolintApplies(comment string) bool {
	t := strings.TrimSpace(strings.TrimPrefix(comment, "//"))
	if t == "nolint" {
		return true
	}
	if !strings.HasPrefix(t, "nolint:") {
		return false
	}
	list := strings.TrimPrefix(t, "nolint:")
	if i := strings.IndexByte(list, ' '); i >= 0 {
		list = list[:i] // drop any trailing "// explanation"
	}
	for _, name := range strings.Split(list, ",") {
		switch strings.TrimSpace(name) {
		case "secmem-lint", "all":
			return true
		}
	}
	return false
}

// --- shared AST helpers ---

// rootIdent walks selector/index/slice/deref/paren chains down to the
// identifier they are rooted at, or nil if the expression is not rooted at a
// plain identifier.
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
		case *ast.SliceExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// withinNode reports whether pos falls inside node's source range.
func withinNode(pos token.Pos, node ast.Node) bool {
	return pos >= node.Pos() && pos < node.End()
}

// report emits a finding with the shared secmem-lint prefix. The strict-mode
// checks, which run over the whole package rather than one closure, use it
// directly; the closure checks go through checker.report for deduplication.
func report(pass *analysis.Pass, pos token.Pos, msg string) {
	pass.Report(analysis.Diagnostic{Pos: pos, Message: diagPrefix + msg})
}
