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
		"initInput": ws.initInput[:cap(ws.initInput)],
	}
	if len(ws.b) > 0 {
		r["B"] = unsafe.Slice((*byte)(unsafe.Pointer(&ws.b[0])), len(ws.b)*int(unsafe.Sizeof(block{})))
	}
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
			case "initInput", "hashIn", "hashState":
				// Derive wipes these itself as soon as it is done with them;
				// TestInitInputWiped covers the control for initInput.
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
	}
}

// TestInitInputWiped pins the H0 input separately: it is the one region
// that holds the raw password, and Derive itself must clear it before
// Wipe, because it is done with it as soon as H0 exists. The control is
// that the buffer was sized to hold the password at all.
func TestInitInputWiped(t *testing.T) {
	ws := NewWorkspace(8, 1)
	password := []byte("the password itself, verbatim, in the H0 input")
	Derive(make([]byte, 32), ModeID, password, []byte("salt"), nil, nil, 1, ws)
	if cap(ws.initInput) < 24+16+len(password)+4 {
		t.Fatalf("control failed: H0 input buffer capacity %d cannot have held the password", cap(ws.initInput))
	}
	if bytes.Contains(ws.initInput[:cap(ws.initInput)], password) {
		t.Fatal("password still present in the H0 input buffer after Derive")
	}
	if !isZero(ws.initInput[:cap(ws.initInput)]) {
		t.Fatal("H0 input buffer not zero after Derive")
	}
	ws.Wipe()
}
