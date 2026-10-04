package argon2

import (
	"bytes"
	"testing"
	"unsafe"
)

// workspaceResidue returns the byte views of every region a Workspace owns,
// named, so a test can say which one held residue.
func workspaceResidue(ws *Workspace) map[string][]byte {
	r := map[string][]byte{
		"h0":        ws.h0[:],
		"block0":    ws.block0[:],
		"hashIn":    ws.hashIn[:],
		"hashState": ws.hashState[:],
		"h0Block":   ws.h0Block[:],
		"h0Chain":   unsafe.Slice((*byte)(unsafe.Pointer(ws.h0Chain)), h0ChainSize),
	}
	r["B"] = unsafe.Slice((*byte)(unsafe.Pointer(&ws.b[0])), len(ws.b)*int(unsafe.Sizeof(block{})))
	for i := range ws.lanes {
		s := &ws.lanes[i]
		r["lane.addresses"] = append(r["lane.addresses"], unsafe.Slice((*byte)(unsafe.Pointer(&s.addresses)), 1024)...)
		r["lane.in"] = append(r["lane.in"], unsafe.Slice((*byte)(unsafe.Pointer(&s.in)), 1024)...)
		r["lane.tmp"] = append(r["lane.tmp"], unsafe.Slice((*byte)(unsafe.Pointer(&s.tmp)), 1024)...)
	}
	return r
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestWorkspaceWipe is acceptance criterion 2 made deterministic: the test
// owns the Workspace, so after Derive it can look at every region the
// algorithm used. The first half is the control: each region the algorithm
// writes must be non-zero after Derive, or the assertion in the second half
// would be vacuous. hashState is only used for outputs longer than 64
// bytes, so it is exercised with a 100-byte tag. The shared constant
// zeroBlock must still be zero afterwards: if it is ever written the
// derivation is wrong, not just leaky.
func TestWorkspaceWipe(t *testing.T) {
	for _, mode := range []Mode{ModeI, ModeID, ModeD} {
		ws := NewWorkspace(64, 2)
		out := make([]byte, 100)
		Derive(out, mode, []byte("password"), []byte("0123456789abcdef"), []byte("K"), []byte("X"), 2, ws)

		for name, region := range workspaceResidue(ws) {
			switch name {
			case "h0Block", "h0Chain", "hashIn", "hashState":
				// Derive wipes these itself as soon as it is done with them;
				// TestH0StateWiped covers the control for the H0 pair.
				if !isZero(region) {
					t.Errorf("mode %d: %s not cleared by Derive itself", mode, name)
				}
			case "lane.addresses", "lane.in":
				// Only the data-independent phases write these, and `in` is
				// reset at the start of every segment, so after Derive it is
				// non-zero only when the LAST segment was data-independent:
				// Argon2i. addresses keeps the last generated block in both
				// i and id.
				wantDirty := mode == ModeI || (mode == ModeID && name == "lane.addresses")
				if !wantDirty && !isZero(region) {
					t.Errorf("mode %d: %s written by a data-dependent segment", mode, name)
				}
				if wantDirty && isZero(region) {
					t.Errorf("mode %d: control failed: %s is all zero after Derive, the wipe assertion would be vacuous", mode, name)
				}
			default:
				if isZero(region) {
					t.Errorf("mode %d: control failed: %s is all zero after Derive, the wipe assertion would be vacuous", mode, name)
				}
			}
		}

		ws.Wipe()
		for name, region := range workspaceResidue(ws) {
			if !isZero(region) {
				t.Errorf("mode %d: %s holds residue after Wipe", mode, name)
			}
		}
		if !isZero(unsafe.Slice((*byte)(unsafe.Pointer(&zeroBlock)), 1024)) {
			t.Fatalf("mode %d: the shared zeroBlock was written", mode)
		}
		if !isZero(ws.mem) {
			t.Errorf("mode %d: bytes of the region outside the named views hold residue after Wipe", mode)
		}
	}
}

// TestBind_LayoutCoversRegion pins that the views tile the region exactly:
// every byte of mem belongs to one named view, so a residue test over the
// views is a residue test over the region. It also pins Bind's refusals.
func TestBind_LayoutCoversRegion(t *testing.T) {
	ws := NewWorkspace(64, 3)
	total := 0
	for _, region := range workspaceResidue(ws) {
		total += len(region)
	}
	if total != len(ws.mem) || len(ws.mem) != WorkspaceSize(64, 3) {
		t.Fatalf("views cover %d bytes, region is %d, WorkspaceSize says %d", total, len(ws.mem), WorkspaceSize(64, 3))
	}
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	mustPanic("short region", func() { Bind(make([]byte, WorkspaceSize(64, 3)-1), 64, 3) })
	mustPanic("misaligned region", func() { Bind(make([]byte, WorkspaceSize(64, 1)+8)[1:], 64, 1) })
}

// TestH0StateWiped pins the H0 staging block and chaining value separately:
// the block is the one region that holds the raw password, and initHash
// itself must clear both, because it is done with them as soon as H0 exists.
// The control absorbs the same password without finalising: its tail must
// then be in the block and the chaining value non-zero, or the assertions
// after it would be vacuous.
func TestH0StateWiped(t *testing.T) {
	ws := NewWorkspace(8, 1)
	password := bytes.Repeat([]byte("the password itself, verbatim, in the H0 input; "), 8)
	chain := unsafe.Slice((*byte)(unsafe.Pointer(ws.h0Chain)), h0ChainSize)

	*ws.h0Chain = iv
	var c [2]uint64
	ws.h0Absorb(&c, 0, password)
	if !bytes.Contains(ws.h0Block[:], password[len(password)-32:]) {
		t.Fatal("control failed: absorbing the password did not leave its tail in the staging block")
	}
	if c[0] == 0 || isZero(chain) {
		t.Fatal("control failed: absorbing the password compressed no block")
	}

	ws.initHash(password, nil, nil, nil, 1, 32, ModeID)
	if !isZero(ws.h0Block[:]) {
		t.Fatal("H0 staging block not zero after initHash")
	}
	if !isZero(chain) {
		t.Fatal("H0 chaining value not zero after initHash")
	}
	if isZero(ws.h0[:]) {
		t.Fatal("control failed: initHash produced no H0")
	}
	ws.Wipe()
}
