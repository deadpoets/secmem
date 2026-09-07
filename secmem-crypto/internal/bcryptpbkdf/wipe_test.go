package bcryptpbkdf

import (
	"bytes"
	"testing"
	"unsafe"
)

// workspaceResidue returns the byte views of every region a Workspace owns,
// named, so a test can say which one held residue.
func workspaceResidue(ws *Workspace) map[string][]byte {
	return map[string][]byte{
		"cipher":  unsafe.Slice((*byte)(unsafe.Pointer(&ws.c)), unsafe.Sizeof(ws.c)),
		"shapass": ws.shapass[:],
		"shasalt": ws.shasalt[:],
		"tmp":     ws.tmp[:],
		"out":     ws.out[:],
		"saltIn":  ws.saltIn[:],
	}
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestWorkspaceWipe is the fork's acceptance criterion made deterministic:
// the test owns the Workspace, so after Derive it can look at every region
// the algorithm used. The first half is the control — each region must be
// non-zero after Derive, or the wipe assertion would be vacuous; the second
// half wipes and requires all of them zero, and requires that the passphrase
// and the derived key are then nowhere in the Workspace.
func TestWorkspaceWipe(t *testing.T) {
	ws := NewWorkspace()
	password := []byte("the passphrase itself, verbatim")
	salt := []byte("0123456789abcdef")
	out := make([]byte, 48)
	if err := Derive(out, password, salt, 2, ws); err != nil {
		t.Fatal(err)
	}
	for name, region := range workspaceResidue(ws) {
		if isZero(region) {
			t.Errorf("control failed: %s is all zero after Derive, the wipe assertion would be vacuous", name)
		}
	}
	// The reserve holds the salt (not secret) — but nothing else: a
	// passphrase byte there would be a bug in the reserve handling.
	if !bytes.HasPrefix(ws.saltIn[:], salt) {
		t.Error("control failed: the reserve does not start with the salt")
	}
	if bytes.Contains(ws.saltIn[:], password) {
		t.Error("the passphrase was written into the salt reserve")
	}

	ws.Wipe()
	for name, region := range workspaceResidue(ws) {
		if !isZero(region) {
			t.Errorf("%s holds residue after Wipe", name)
		}
	}
	whole := unsafe.Slice((*byte)(unsafe.Pointer(ws)), Size)
	if !isZero(whole) {
		t.Error("bytes of the Workspace outside the named views hold residue after Wipe")
	}
	if isZero(out) {
		t.Fatal("control failed: Wipe reached the caller's output")
	}
}

// TestViewsCoverWorkspace pins that the named views tile the Workspace
// exactly, so a residue test over the views is a residue test over the
// whole struct.
func TestViewsCoverWorkspace(t *testing.T) {
	ws := NewWorkspace()
	total := 0
	for _, region := range workspaceResidue(ws) {
		total += len(region)
	}
	if total != Size {
		t.Fatalf("views cover %d bytes, Workspace is %d", total, Size)
	}
}
