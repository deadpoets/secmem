package secmemlint

import (
	"fmt"
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// reentrantUnsafe is the set of secmem access methods that take the buffer's
// lock. Calling any of them on the SAME buffer from inside its own borrowing
// closure violates the documented non-reentrancy contract and deadlocks.
var reentrantUnsafe = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"WithBytes": true, "WithBytesErr": true,
	"WithScalar": true, "WithSeed": true, "WithDER": true,
	"CopyOut": true, "CopyIn": true, "ConstantTimeEqual": true,
	"ExposeString": true, "ByteAt": true, "WriteTo": true, "ReadFrom": true,
	"Truncate": true, "Seal": true, "Unseal": true,
	"ReadOnly": true, "ReadWrite": true, "Destroy": true,
}

// checkReentrancy flags an access method called on the SAME buffer inside its own
// borrowing closure. A DIFFERENT buffer (the documented decrypt-into pattern) is
// resolved by object identity and is not flagged.
func checkReentrancy(pass *analysis.Pass, acc accessor, sup *suppressor) {
	if acc.recv == nil {
		return
	}
	recvObj := pass.TypesInfo.ObjectOf(acc.recv)
	if recvObj == nil {
		return
	}
	ast.Inspect(acc.fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !reentrantUnsafe[sel.Sel.Name] {
			return true
		}
		inner, ok := sel.X.(*ast.Ident)
		if !ok || pass.TypesInfo.ObjectOf(inner) != recvObj {
			return true
		}
		if !sup.suppressed(pass, call.Pos()) {
			report(pass, call.Pos(), fmt.Sprintf(
				"%s called on the same buffer inside its own borrowing closure; secmem access methods are not reentrant and will deadlock",
				sel.Sel.Name))
		}
		return true
	})
}
