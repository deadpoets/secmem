package secmemlint

import (
	"fmt"
	"go/ast"
	"go/types"
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

	// SetByteAt takes the EXCLUSIVE lock, so calling it inside a borrow is an
	// unconditional self-deadlock — the most certain member of this set, and it
	// was missing while its read counterpart ByteAt was listed.
	"SetByteAt": true,

	// The rLock inspectors. A nested read acquire looks harmless, but this
	// package's lock is writer-preferring: rLock waits while any writer is
	// queued, so a second read taken from inside a borrow deadlocks as soon as
	// a writer arrives between the two — a Destroy or an emergency wipe is
	// enough. That makes them load-bearing rather than merely untidy.
	"Len": true, "MappedLen": true, "IsSealed": true, "IsDestroyed": true,

	// ArenaSlot.Release re-takes the arena's read lock that the slot's own
	// borrow already holds — the same writer-preferring hazard as Len.
	"Release": true,
}

// arenaExclusive are the SecureArena methods that take the arena's EXCLUSIVE
// lock (securearena.go: mu.lock). A slot borrow holds that lock's read side
// for the whole callback, so calling one of these on the slot's arena from
// inside the borrow is a certain self-deadlock. Acquire and LiveCount take
// only the allocation mutex, which is never held across a callback, and are
// safe.
var arenaExclusive = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"Destroy": true, "ReadOnly": true, "ReadWrite": true,
}

// checkReentrancy flags an access method called on the SAME buffer inside its
// own borrowing closure. A DIFFERENT buffer (the documented decrypt-into
// pattern) is resolved by object identity and is not flagged.
//
// Receivers are compared as identity chains, so a buffer held in a struct
// field is covered, and a local bound once to the buffer (b2 := buf) or to
// one of its methods (l := buf.Len) resolves to the buffer.
//
// Only calls that run synchronously inside the closure count. A func literal
// that is assigned, returned, sent or launched with go runs after the lease
// (or on another goroutine) and is skipped; one that is invoked in place,
// deferred, or passed to a call is walked.
func (c *checker) checkReentrancy(acc accessor) {
	slot := namedTypeKey(c.pass.TypesInfo.TypeOf(acc.recvExpr)) == secmemPkg+".ArenaSlot"
	if len(acc.recv) == 0 && !slot {
		return
	}
	arena, arenaKnown := c.slotArena(acc)
	kind := "buffer"
	if slot {
		kind = "slot"
	}

	var stack []ast.Node
	ast.Inspect(acc.body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if lit, ok := n.(*ast.FuncLit); ok && !runsSynchronously(lit, stack) {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.methodSelector(call.Fun)
		if !ok {
			return true
		}
		if selection, ok := c.pass.TypesInfo.Selections[sel]; !ok || selection.Kind() != types.MethodVal {
			return true
		}
		name := sel.Sel.Name
		if reentrantUnsafe[name] {
			if inner, ok := c.receiverKey(sel.X, 0); ok && sameReceiver(acc.recv, inner) {
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on the same %s inside its own borrowing closure; secmem access methods are not reentrant and will deadlock",
					name, kind))
				return true
			}
		}
		if slot && arenaExclusive[name] && namedTypeKey(c.pass.TypesInfo.TypeOf(sel.X)) == secmemPkg+".SecureArena" {
			inner, ok := c.receiverKey(sel.X, 0)
			switch {
			case arenaKnown && ok && sameReceiver(arena, inner):
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on the slot's arena inside a slot borrow; it takes the arena's exclusive lock, which the borrow holds for reading, and will deadlock",
					name))
			case !arenaKnown && strict:
				c.report(call.Pos(), fmt.Sprintf(
					"%s called on a SecureArena inside a slot borrow whose arena cannot be resolved; if it is this slot's arena the call will deadlock",
					name))
			}
		}
		return true
	})
}

// slotArena resolves the arena a slot receiver was acquired from — the
// receiver of the Acquire call in slot, err := arena.Acquire() — when the slot
// is a local bound exactly once that way.
func (c *checker) slotArena(acc accessor) ([]types.Object, bool) {
	if len(acc.recv) != 1 {
		return nil, false
	}
	v, ok := acc.recv[0].(*types.Var)
	if !ok {
		return nil, false
	}
	call, idx, ok := c.defs.singleTupleDef(v)
	if !ok || idx != 0 {
		return nil, false
	}
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Acquire" {
		return nil, false
	}
	if namedTypeKey(c.pass.TypesInfo.TypeOf(sel.X)) != secmemPkg+".SecureArena" {
		return nil, false
	}
	return c.receiverKey(sel.X, 0)
}

// runsSynchronously reports whether a func literal (the last node on stack)
// executes before its enclosing closure returns: it is invoked in place,
// deferred, or passed as an argument to a call that is not a go statement.
func runsSynchronously(lit *ast.FuncLit, stack []ast.Node) bool {
	if len(stack) < 2 {
		return true
	}
	parent := stack[len(stack)-2]
	call, ok := parent.(*ast.CallExpr)
	if !ok {
		return false // assigned, returned, sent, stored in a literal
	}
	if len(stack) >= 3 {
		if _, ok := stack[len(stack)-3].(*ast.GoStmt); ok {
			return false
		}
	}
	_ = lit
	return call != nil
}
