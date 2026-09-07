package bcryptpbkdf

import "testing"

// BenchmarkDerive_OpenSSHDefault is OpenSSH's profile: 16 rounds, a 16-byte
// salt, 48 bytes of key+IV. The algorithm is upstream's, so the cost is
// upstream's; the number is here so a port can see a regression.
func BenchmarkDerive_OpenSSHDefault(b *testing.B) {
	ws := NewWorkspace()
	defer ws.Wipe()
	out := make([]byte, 48)
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	b.ReportAllocs()
	for b.Loop() {
		if err := Derive(out, password, salt, 16, ws); err != nil {
			b.Fatal(err)
		}
	}
}
