package secmemcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deadpoets/secmem"
)

// The two tests in this file hold one property from both ends: a core option
// given to any call in this package reaches every SecureBuffer that call —
// or the key it built, later — allocates. The first reads the source and
// fails when an entry point that can allocate has nowhere to take options
// from; the second runs every family of entry point and counts.

// apiFunc is one function or method of the package, as the source walk
// sees it.
type apiFunc struct {
	name     string // "Func" or "Type.Method"
	recv     string // receiver type name, "" for a function
	exported bool   // the name is exported, and so is the receiver type
	variadic bool   // the last parameter is ...Option
	calls    map[string]bool
	direct   []token.Position // calls to a core constructor in the body
}

// parsePackageFuncs reads every non-test file of the package and returns
// its functions, the func-valued package variables (which are functions for
// this purpose), and the struct types that carry buffer options.
//
// Edges are by name, deliberately over-approximate: a selector x.Name is an
// edge to every method called Name in the package, since without type
// information the walk cannot tell whose it is. An over-approximation can
// only make the test stricter.
func parsePackageFuncs(t *testing.T) (funcs map[string]*apiFunc, carriers map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}

	funcs = map[string]*apiFunc{}
	carriers = map[string]bool{}
	methodsNamed := map[string][]string{}
	bodies := map[string]ast.Node{}
	isOptionVariadic := func(ft *ast.FuncType) bool {
		if ft.Params == nil || len(ft.Params.List) == 0 {
			return false
		}
		last, ok := ft.Params.List[len(ft.Params.List)-1].Type.(*ast.Ellipsis)
		if !ok {
			return false
		}
		id, ok := last.Elt.(*ast.Ident)
		return ok && id.Name == "Option"
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				fn := &apiFunc{name: d.Name.Name, exported: d.Name.IsExported(), variadic: isOptionVariadic(d.Type)}
				if d.Recv != nil && len(d.Recv.List) == 1 {
					typ := d.Recv.List[0].Type
					if star, ok := typ.(*ast.StarExpr); ok {
						typ = star.X
					}
					if id, ok := typ.(*ast.Ident); ok {
						fn.recv = id.Name
						fn.name = id.Name + "." + d.Name.Name
						fn.exported = fn.exported && id.IsExported()
						methodsNamed[d.Name.Name] = append(methodsNamed[d.Name.Name], fn.name)
					}
				}
				funcs[fn.name] = fn
				if d.Body != nil {
					bodies[fn.name] = d.Body
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for i, v := range s.Values {
							if lit, ok := v.(*ast.FuncLit); ok && i < len(s.Names) {
								name := s.Names[i].Name
								funcs[name] = &apiFunc{name: name}
								bodies[name] = lit.Body
							}
						}
					case *ast.TypeSpec:
						st, ok := s.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, field := range st.Fields.List {
							if id, ok := field.Type.(*ast.Ident); ok && id.Name == "bufferOptions" {
								carriers[s.Name.Name] = true
							}
						}
					}
				}
			}
		}
	}

	for name, body := range bodies {
		fn := funcs[name]
		fn.calls = map[string]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "secmem" && strings.HasPrefix(x.Sel.Name, "New") {
					fn.direct = append(fn.direct, fset.Position(x.Pos()))
				}
				for _, m := range methodsNamed[x.Sel.Name] {
					fn.calls[m] = true
				}
			case *ast.Ident:
				if _, ok := funcs[x.Name]; ok {
					fn.calls[x.Name] = true
				}
			}
			return true
		})
	}
	return funcs, carriers
}

// TestAllocatingEntryPointsTakeOptions fails when an exported function that
// can reach a core constructor has no way to be given core options: it must
// either take ...Option itself or be a method of a type that stores the
// options it was built with. It also pins the single choke point that makes
// "reach" decidable: only bufferOptions' methods call the core's
// constructors, so an allocation cannot be added that ignores them.
func TestAllocatingEntryPointsTakeOptions(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("reads the package source, which a wasm test binary is not run beside")
	}
	funcs, carriers := parsePackageFuncs(t)

	reaches := map[string]bool{}
	for name, fn := range funcs {
		if len(fn.direct) == 0 {
			continue
		}
		reaches[name] = true
		if fn.recv != "bufferOptions" {
			for _, pos := range fn.direct {
				t.Errorf("%s: %s calls a core constructor directly; allocate through the call's bufferOptions so that BufferOptions reaches it", pos, name)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if reaches[name] {
				continue
			}
			for callee := range fn.calls {
				if reaches[callee] {
					reaches[name], changed = true, true
					break
				}
			}
		}
	}

	// Controls: the walk must see the allocations it exists to police, or a
	// pass means nothing.
	// One space-separated string, not a slice literal: a quoted name ending
	// in "Passphrase" or "Secret" followed by a comma and another quoted
	// string is the shape the secret scanner's generic-key rule matches.
	for _, known := range strings.Fields(`
		GenerateEd25519Signer ParsePrivateKey ParsePrivateKeyWithPassphrase X25519Key.SharedSecret
		MLKEM768Key.Decapsulate Ed25519Signer.MarshalOpenSSHPrivateKey BcryptPBKDFInto HKDFSHA256Into
		NewArgon2Pool GenerateDicewarePassphrase Encapsulate GenerateRSASigner
	`) {
		if !reaches[known] {
			t.Errorf("control failed: the source walk does not see %s reach a core constructor", known)
		}
	}

	var names []string
	for name := range reaches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fn := funcs[name]
		if !fn.exported || fn.variadic || (fn.recv != "" && carriers[fn.recv]) {
			continue
		}
		if fn.recv != "" {
			t.Errorf("%s can allocate a SecureBuffer, but %s does not store the bufferOptions it was built with", name, fn.recv)
		} else {
			t.Errorf("%s can allocate a SecureBuffer but does not take ...Option", name)
		}
	}
}

// countingOption is a core option that counts how often a core constructor
// applies it. secmem.Option's parameter type is unexported, so the function
// is made by reflection; applying it changes nothing about the allocation.
func countingOption() (secmem.Option, *atomic.Int64) {
	var n atomic.Int64
	fn := reflect.MakeFunc(reflect.TypeOf(secmem.WithInsecureFallback()), func([]reflect.Value) []reflect.Value {
		n.Add(1)
		return nil
	})
	return fn.Interface().(secmem.Option), &n
}

// TestBufferOptionsReachEveryAllocation runs each family of entry point with
// a counting core option and compares two numbers that must be equal: how
// many SecureBuffers were created during the call (LockOrder is a
// process-wide creation counter, read off a probe buffer before and after)
// and how many times a core constructor applied the option. A buffer
// allocated without the caller's options is created but not counted.
func TestBufferOptionsReachEveryAllocation(t *testing.T) {
	counting, applied := countingOption()
	// WithInsecureFallback rides along so the test means the same thing on a
	// platform with no lockable memory, where nothing allocates without it.
	with := BufferOptions(counting, secmem.WithInsecureFallback())
	allow := AllowHeapTransients()

	ordinal := func() uint64 {
		t.Helper()
		b, err := secmem.NewEmptyBuffer(1, secmem.WithInsecureFallback())
		if err != nil {
			t.Skipf("no memory for the probe buffer: %v", err)
		}
		defer b.Destroy()
		return b.LockOrder()
	}
	if a, b := ordinal(), ordinal(); b != a+1 {
		t.Fatalf("control failed: consecutive buffers have LockOrder %d and %d; it is not a creation counter", a, b)
	}

	// measure runs f and requires every buffer created in it to have been
	// given the option, and at least atLeast of them to exist (so that a call
	// that silently allocates nothing does not pass as "all forwarded").
	measure := func(name string, atLeast uint64, f func()) {
		t.Helper()
		before, start := applied.Load(), ordinal()
		f()
		created := ordinal() - start - 1
		got := uint64(applied.Load() - before)
		switch {
		case created != got:
			t.Errorf("%s: %d SecureBuffers were created, %d of them with the caller's core options", name, created, got)
		case created < atLeast:
			t.Errorf("%s: created %d SecureBuffers, expected at least %d; the measurement is not seeing the call", name, created, atLeast)
		}
	}
	ok := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	newBuf := func(n int) *secmem.SecureBuffer {
		t.Helper()
		b, err := secmem.NewEmptyBuffer(n, secmem.WithInsecureFallback())
		ok(err)
		ok(b.WithBytesErr(func(p []byte) error { _, err := rand.Read(p); return err }))
		t.Cleanup(func() { b.Destroy() })
		return b
	}
	read := func(b *secmem.SecureBuffer) []byte {
		t.Helper()
		var out []byte
		ok(b.WithBytesErr(func(p []byte) error {
			out = bytes.Clone(p) //nolint:secmem-lint // test egress of a throwaway test key, to feed it back to the parsers
			return nil
		}))
		return out
	}
	passphrase := []byte(testPassphrase)

	// Ed25519: generated, wrapped, and what each marshals later.
	var ed *Ed25519Signer
	measure("GenerateEd25519Signer", 1, func() {
		var err error
		ed, err = GenerateEd25519Signer(with)
		ok(err)
	})
	defer ed.Destroy()
	var sshPlain, sshEncrypted []byte
	measure("Ed25519Signer.MarshalOpenSSHPrivateKey", 2, func() {
		out, err := ed.MarshalOpenSSHPrivateKey("c")
		ok(err)
		sshPlain = read(out)
		out.Destroy()
	})
	measure("Ed25519Signer.MarshalOpenSSHPrivateKeyWithPassphraseParams", 3, func() {
		out, err := ed.MarshalOpenSSHPrivateKeyWithPassphraseParams("c", passphrase, OpenSSHPassphraseParams{Rounds: 1})
		ok(err)
		sshEncrypted = read(out)
		out.Destroy()
	})
	// A wrapped key allocates nothing at construction (the seed buffer is
	// the caller's, made before the measurement); what is measured is that
	// the options given then are the ones its methods use later.
	edSeed, xScalar, kemSeed := newBuf(ed25519.SeedSize), newBuf(32), newBuf(64)
	measure("NewEd25519Signer, then Marshal", 2, func() {
		s, err := NewEd25519Signer(edSeed, with)
		ok(err)
		defer s.Destroy()
		out, err := s.MarshalOpenSSHPrivateKey("c")
		ok(err)
		out.Destroy()
	})

	// X25519.
	var peer [32]byte
	peer[0] = 9
	measure("GenerateX25519Key, then SharedSecret", 2, func() {
		k, err := GenerateX25519Key(with)
		ok(err)
		defer k.Destroy()
		ss, err := k.SharedSecret(peer)
		ok(err)
		ss.Destroy()
	})
	measure("NewX25519Key, then SharedSecret", 1, func() {
		k, err := NewX25519Key(xScalar, with)
		ok(err)
		defer k.Destroy()
		ss, err := k.SharedSecret(peer)
		ok(err)
		ss.Destroy()
	})

	// ML-KEM, both sides.
	measure("GenerateMLKEM768Key, Encapsulate, Decapsulate", 3, func() {
		k, err := GenerateMLKEM768Key(with, allow)
		ok(err)
		defer k.Destroy()
		ek, err := k.EncapsulationKeyBytes()
		ok(err)
		ct, ss, err := Encapsulate(ek, with)
		ok(err)
		ss.Destroy()
		got, err := k.Decapsulate(ct)
		ok(err)
		got.Destroy()
	})
	measure("NewMLKEM768Key, then Decapsulate", 2, func() {
		k, err := NewMLKEM768Key(kemSeed, with, allow)
		ok(err)
		defer k.Destroy()
		ek, err := k.EncapsulationKeyBytes()
		ok(err)
		ct, ss, err := Encapsulate(ek, with)
		ok(err)
		ss.Destroy()
		got, err := k.Decapsulate(ct)
		ok(err)
		got.Destroy()
	})

	// ECDSA and RSA generation.
	measure("GenerateECDSASigner", 1, func() {
		s, err := GenerateECDSASigner(elliptic.P256(), with, allow)
		ok(err)
		s.Destroy()
	})
	measure("GenerateRSASigner", 1, func() {
		s, err := GenerateRSASigner(2048, with, allow)
		ok(err)
		s.Destroy()
	})

	// The parsers: every container, and a parsed key's later allocations.
	toPEM := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	ok(err)
	edP8, err := x509.MarshalPKCS8PrivateKey(edPriv)
	ok(err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ok(err)
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	ok(err)
	rsaKey := testRSAKey()
	parse := func(name string, atLeast uint64, data []byte) {
		t.Helper()
		measure("ParsePrivateKey/"+name, atLeast, func() {
			s, err := ParsePrivateKey(data, with, allow)
			ok(err)
			s.Destroy()
		})
	}
	parse("Ed25519 PKCS#8 PEM", 2, toPEM("PRIVATE KEY", edP8))
	parse("Ed25519 PKCS#8 DER", 2, edP8)
	parse("Ed25519 OpenSSH", 2, sshPlain)
	parse("ECDSA SEC 1 PEM", 2, toPEM("EC PRIVATE KEY", ecSEC1))
	parse("RSA PKCS#1 PEM", 1, toPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	parse("RSA OpenSSH", 2, newSyntheticRSA(t, 1024, 1024).openssh(t))
	measure("ParsePrivateKey, then Marshal", 4, func() {
		s, err := ParsePrivateKey(edP8, with)
		ok(err)
		defer s.Destroy()
		out, err := s.(*Ed25519Signer).MarshalOpenSSHPrivateKey("c")
		ok(err)
		out.Destroy()
	})
	measure("ParsePrivateKeyWithPassphrase/OpenSSH", 4, func() {
		s, err := ParsePrivateKeyWithPassphrase(sshEncrypted, passphrase, with)
		ok(err)
		s.Destroy()
	})
	measure("ParsePrivateKeyWithPassphrase/PKCS#8", 4, func() {
		s, err := ParsePrivateKeyWithPassphrase(encryptPKCS8(t, edP8, pbes2Spec{}), passphrase, with)
		ok(err)
		s.Destroy()
	})

	// Derivations: the ones whose scratch is a locked buffer.
	out32 := newBuf(32)
	long := bytes.Repeat([]byte("i"), 4096) // past the stack region, so the scratch is a buffer
	measure("BcryptPBKDFInto", 1, func() { ok(BcryptPBKDFInto([]byte("p"), []byte("salt"), 1, out32, with)) })
	measure("HMACSHA256Into", 1, func() { ok(HMACSHA256Into([]byte("k"), long, out32, with)) })
	measure("HKDFSHA256Into", 1, func() { ok(HKDFSHA256Into([]byte("k"), nil, long, out32, with)) })
	measure("GenerateDicewarePassphrase", 1, func() {
		p, err := GenerateDicewarePassphrase(4, with)
		ok(err)
		p.Destroy()
	})

	// Argon2's locked workspaces.
	measure("NewArgon2Workspace", 1, func() {
		w, err := NewArgon2Workspace(64, 1, with)
		if err != nil {
			t.Skipf("lock budget: %v", err)
		}
		w.Destroy()
	})
	measure("NewArgon2Pool", 2, func() {
		p, err := NewArgon2Pool(2, 64, 1, with)
		if err != nil {
			t.Skipf("lock budget: %v", err)
		}
		p.Destroy()
	})
}

// TestBufferOptions_NoSecureMemoryPlatform is the case the option exists
// for, and runs only where it applies: a platform on which the core has no
// lockable memory (none of the CI platforms; GOOS=js under node is one that
// can be run by hand). There, every allocating call fails closed without
// the core's opt-in, and with it the buffers a call returns — and the ones
// the resulting key returns later — are the core's insecure fallback.
func TestBufferOptions_NoSecureMemoryPlatform(t *testing.T) {
	if probe, err := secmem.NewEmptyBuffer(1); err == nil {
		probe.Destroy()
		t.Skip("this platform has lockable memory; BufferOptions(WithInsecureFallback()) changes nothing here")
	} else if !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Skipf("allocation failed for another reason: %v", err)
	}
	insecure := BufferOptions(secmem.WithInsecureFallback())

	if _, err := GenerateEd25519Signer(); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateEd25519Signer without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	if _, err := GenerateX25519Key(); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateX25519Key without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	if _, err := GenerateDicewarePassphrase(4); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("GenerateDicewarePassphrase without the opt-in: %v, want ErrNoSecureMemory", err)
	}

	mustInsecure := func(name string, b *secmem.SecureBuffer, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s with the opt-in: %v", name, err)
		}
		defer b.Destroy()
		if !b.Capabilities().Insecure {
			t.Fatalf("%s: the buffer does not report the insecure fallback", name)
		}
	}
	ed, err := GenerateEd25519Signer(insecure)
	if err != nil {
		t.Fatalf("GenerateEd25519Signer with the opt-in: %v", err)
	}
	defer ed.Destroy()
	out, err := ed.MarshalOpenSSHPrivateKeyWithPassphraseParams("c", []byte(testPassphrase), OpenSSHPassphraseParams{Rounds: 1})
	mustInsecure("Marshal on a key built with the opt-in", out, err)

	x, err := GenerateX25519Key(insecure)
	if err != nil {
		t.Fatalf("GenerateX25519Key with the opt-in: %v", err)
	}
	defer x.Destroy()
	ss, err := x.SharedSecret([32]byte{9})
	mustInsecure("SharedSecret on a key built with the opt-in", ss, err)

	p, err := GenerateDicewarePassphrase(4, insecure)
	mustInsecure("GenerateDicewarePassphrase", p, err)

	var pemKey []byte
	plain, err := ed.MarshalOpenSSHPrivateKey("c")
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.WithBytesErr(func(b []byte) error {
		pemKey = bytes.Clone(b) //nolint:secmem-lint // test egress of a throwaway test key, to feed it back to the parser
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	plain.Destroy()
	if _, err := ParsePrivateKey(pemKey); !errors.Is(err, secmem.ErrNoSecureMemory) {
		t.Fatalf("ParsePrivateKey without the opt-in: %v, want ErrNoSecureMemory", err)
	}
	s, err := ParsePrivateKey(pemKey, insecure)
	if err != nil {
		t.Fatalf("ParsePrivateKey with the opt-in: %v", err)
	}
	s.Destroy()
}

// TestPackageDocLivesInDocGo: a comment directly above a package clause is
// package documentation, and godoc concatenates every file's. A file header
// that explains the file is kept apart from the clause by a blank line, so
// the published overview is doc.go's and nothing else.
func TestPackageDocLivesInDocGo(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skip("reads the package source, which a wasm test binary is not run beside")
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	sawDoc := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ParseComments|parser.PackageClauseOnly)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case e.Name() == "doc.go":
			sawDoc = f.Doc != nil && strings.HasPrefix(f.Doc.Text(), "Package secmemcrypto ")
		case f.Doc != nil:
			t.Errorf("%s: its header comment is attached to the package clause and is published as package documentation; put a blank line between them", e.Name())
		}
	}
	if !sawDoc {
		t.Error("doc.go does not carry the package documentation")
	}
}
