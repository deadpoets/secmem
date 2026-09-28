// Package aggregates covers writes through a local struct or array VALUE. The
// value's own storage is inside the closure, but a slice, pointer or map held
// in one of its fields or elements is wherever that reference points — so a
// local struct is not a blanket "inside": what was stored in the field
// decides. An earlier version of the analyzer treated every local struct or
// array as inside before looking, and every write in aliasesOuter was silent.
package aggregates

import "github.com/deadpoets/secmem"

type holder struct{ b []byte }
type pholder struct{ p *[]byte }
type record struct {
	tag   [4]byte
	inner struct{ dst []byte }
}

var (
	sink     = make([]byte, 64)
	outerMap = map[string][]byte{}
)

// aliasesOuter: each aggregate's field or element holds a reference to memory
// outside the closure, so a write through it lands outside.
func aliasesOuter(buf *secmem.SecureBuffer, out []byte, outp *[]byte) {
	_ = buf.WithBytes(func(b []byte) {
		l := holder{b: sink}
		copy(l.b, b)  // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		l.b[0] = b[0] // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`

		var arr [1][]byte
		arr[0] = out
		copy(arr[0], b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		q := pholder{p: outp}
		*q.p = b // want `secmem-lint: borrowed secret bytes assigned to a pointer target`

		var m struct{ dst []byte }
		m.dst = out
		copy(m.dst, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var r record
		r.inner.dst = out
		copy(r.inner.dst, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		// The alias arrives through the initialiser, keyed or positional, and
		// through a nested literal.
		l2 := holder{out}
		copy(l2.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		r2 := record{inner: struct{ dst []byte }{dst: out}}
		r2.inner.dst = append(r2.inner.dst, b...) // want `secmem-lint: append\(\) copies borrowed secret bytes`

		// A map held in a field is the map it was assigned.
		var mm struct{ m map[string][]byte }
		mm.m = outerMap
		mm.m["k"] = b // want `secmem-lint: borrowed secret bytes assigned to a map or slice element`

		// A slice element that was made fresh on one branch and aliased on
		// another: all elements are pooled, and one outer value is enough.
		var pair [2][]byte
		pair[0] = make([]byte, 4)
		pair[1] = out
		copy(pair[0], b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		_, _, _, _, _, _, _ = l, arr, q, m, r, l2, mm
	})
}

type scratch struct{ b []byte }

func (s *scratch) attach(o []byte) { s.b = o }

func apply(f func([]byte), o []byte) { f(o) }

// methodMayAlias: a pointer-receiver method call takes &s implicitly and may
// store anything into s's fields, so after it s.b is not provably fresh.
func methodMayAlias(buf *secmem.SecureBuffer, out []byte) {
	_ = buf.WithBytes(func(b []byte) {
		var s scratch
		s.attach(out)
		copy(s.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
	})
}

// methodValueMayAlias: a pointer-receiver method VALUE is (&s).attach just as
// the call is, and it may run at any time after it is taken — bound to a
// variable, deferred, or handed to another function — so s.b is not provably
// fresh from the selection on, whether or not the method is ever seen called.
func methodValueMayAlias(buf *secmem.SecureBuffer, out []byte) {
	_ = buf.WithBytes(func(b []byte) {
		var s scratch
		s.b = make([]byte, 4)
		f := s.attach
		f(out)
		copy(s.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var t scratch
		apply(t.attach, out)
		copy(t.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var u scratch
		u.b = make([]byte, 4)
		defer u.attach(out)
		copy(u.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var v scratch
		v.b = make([]byte, 4)
		_ = v.attach
		copy(v.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
	})
}

type pscratch struct {
	s *scratch
	b []byte
}

// pointerReceiverAlreadyPointer: a method value on a receiver that is already
// a pointer takes no local's address, so the value it hangs off is still
// followed — q.s.attach is (q.s).attach, not (&q).s.attach, and q.b stays
// provably fresh. (Taking &s explicitly, as p := &s does, is what stops s
// being followed.)
func pointerReceiverAlreadyPointer(buf *secmem.SecureBuffer, out []byte) {
	_ = buf.WithBytes(func(b []byte) {
		var s scratch
		s.b = make([]byte, 4)
		p := &s
		f := p.attach
		_ = f
		copy(s.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var q pscratch
		q.b = make([]byte, 4)
		q.s = &scratch{}
		g := q.s.attach
		_ = g
		copy(q.b, b) // ok: q's own storage is followed and q.b is fresh
		// q.s.b is reached through the pointer q.s, which is not followed
		// (see notFollowed), fresh or not.
		copy(q.s.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		_ = out
	})
}

// unknownRoots: an aggregate that is a range variable, a parameter of a nested
// literal, or an element of an outer slice was not built inside the closure,
// so its fields are outside like any other unproven local.
func unknownRoots(buf *secmem.SecureBuffer, hs []holder) {
	_ = buf.WithBytes(func(b []byte) {
		for _, h := range hs {
			copy(h.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		}
		func(h holder) {
			copy(h.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		}(hs[0])
		copy(hs[0].b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
	})
}

// notFollowed pins the conservative side of the rule: a field reached from a
// value copied out of another variable, or from a value whose address has been
// taken, is not provably fresh and is reported as outside — even though here
// the memory is in fact inside. Declare scratch memory in the aggregate that
// is written through, and do not take its address.
func notFollowed(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		var m holder
		m.b = make([]byte, 4)
		l := m
		copy(l.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var r record
		p := &r
		r.inner.dst = make([]byte, 4)
		copy(r.inner.dst, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
		_ = p
	})
}

// freshInside is the documented scratch idiom and must stay clean: an array
// local written directly, a struct with an array field written directly, a
// struct field that is a slice made fresh inside the closure, a field holding
// the borrowed slice itself, and a fresh pointer to a local aggregate.
func freshInside(buf *secmem.SecureBuffer) {
	_ = buf.WithBytes(func(b []byte) {
		var a [32]byte
		copy(a[:], b)
		a[0] = b[0]

		var r record
		copy(r.tag[:], b)
		r.tag[1] = b[1]

		var s struct{ b []byte }
		s.b = make([]byte, len(b))
		copy(s.b, b)
		s.b[0] = b[0]
		s.b = append(s.b, b...)
		s.b = s.b[:1]

		t := holder{b: make([]byte, 8)}
		copy(t.b, b)

		u := holder{}
		u.b = append(u.b, b...) // a nil field: append allocates

		var arr [2][]byte
		arr[0] = make([]byte, 4)
		arr[1] = []byte{}
		copy(arr[0], b)
		copy(arr[1], b)

		w := holder{b: b} // the borrowed slice itself, held in a field
		copy(w.b, b[:0])
		w.b[0] = b[1]

		p := &r // r's own storage is still r's; only its reference fields stop being followed
		p.tag[2] = b[2]
		copy(p.tag[:], b)

		var nested struct{ h holder }
		nested.h.b = make([]byte, 4)
		copy(nested.h.b, b)
		nested.h = holder{b: make([]byte, 2)}
		copy(nested.h.b, b)

		var mp struct{ m map[string][]byte }
		mp.m = map[string][]byte{}
		mp.m["k"] = b

		var pp struct{ p *[]byte }
		pp.p = new([]byte)
		*pp.p = b

		_, _, _, _, _, _, _, _, _ = a, s, t, u, arr, w, nested, mp, pp
	})
}

// fill stores an outer slice into dst[0]. It stands for any callee that keeps
// or writes through the slice it is handed; the analyzer does not look inside.
func fill(dst [][]byte, o []byte) { dst[0] = o }

func twoResults() ([]byte, error) { return nil, nil }

// slicedArrayMayAlias: slicing an addressable array takes its address
// implicitly — arr[:] is (&arr)[:] — so whoever holds the slice can store an
// outer reference into arr's elements, on the spot (sl[0] = out) or in a
// callee (fill(s.arr[:], out)). From the slice on, the array's reference-typed
// elements are not provably fresh, exactly as after an explicit &arr.
func slicedArrayMayAlias(buf *secmem.SecureBuffer, out []byte) {
	_ = buf.WithBytes(func(b []byte) {
		var arr [2][]byte
		sl := arr[:]
		sl[0] = out
		copy(arr[0], b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		var s struct{ arr [2][]byte }
		fill(s.arr[:], out)
		copy(s.arr[0], b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		// The array's OWN storage is still inside: slicing a byte array to
		// write into it is the documented scratch idiom and stays clean, as
		// does slicing it again afterwards.
		var a [32]byte
		copy(a[:], b)
		a2 := a[:]
		_ = a2
	})
}

// pinnedMechanisms pins three parts of the aggregate rule that no other case
// in this fixture reaches on its own.
func pinnedMechanisms(buf *secmem.SecureBuffer, out []byte) {
	_ = buf.WithBytes(func(b []byte) {
		// A write to a PREFIX of the path through a literal: n.h = holder{b: out}
		// stores an outer slice at n.h.b although nothing is ever assigned to
		// n.h.b by name, so the writes to every prefix of a path count.
		var n struct{ h holder }
		n.h = holder{b: out}
		copy(n.h.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		// A path assigned one result of a tuple holds whatever the call
		// returned, which the index cannot express as a value: an opaque write.
		var t holder
		t.b, _ = twoResults()
		copy(t.b, b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`

		// A map's contents are not followed, fresh or not: the map itself is a
		// fresh local, but its elements are reached through the map, so m["k"]
		// is outside even though every value in the literal is fresh.
		m := map[string][]byte{"k": make([]byte, 4)}
		copy(m["k"], b) // want `secmem-lint: copy\(\) moves borrowed secret bytes`
	})
}
