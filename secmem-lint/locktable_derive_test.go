package secmemlint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The table test (locktable_test.go) fails for a method nobody has
// classified. The tests here check the classification itself, and the stubs
// the fixtures compile against, by reading what the sources do.

// lockSource is one package's functions, with enough of its types to follow a
// call from a method to the lock.
type lockSource struct {
	funcs   map[string]*ast.FuncDecl            // package-level functions
	methods map[string]map[string]*ast.FuncDecl // type → every method, exported or not
	byName  map[string][]*ast.FuncDecl          // method name → declarations on any type
	fields  map[string]map[string]string        // struct type → field → type as written
	embeds  map[string][]string                 // struct type → embedded same-package types
}

func parseLockSource(t *testing.T, dir, pkgName string) *lockSource {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	src := &lockSource{
		funcs:   make(map[string]*ast.FuncDecl),
		methods: make(map[string]map[string]*ast.FuncDecl),
		byName:  make(map[string][]*ast.FuncDecl),
		fields:  make(map[string]map[string]string),
		embeds:  make(map[string][]string),
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if file.Name.Name != pkgName {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				if d.Recv == nil {
					src.funcs[d.Name.Name] = d
					continue
				}
				recv, _ := baseTypeName(d.Recv.List[0].Type)
				if src.methods[recv] == nil {
					src.methods[recv] = make(map[string]*ast.FuncDecl)
				}
				src.methods[recv][d.Name.Name] = d
				src.byName[d.Name.Name] = append(src.byName[d.Name.Name], d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					src.fields[ts.Name.Name] = make(map[string]string)
					for _, f := range st.Fields.List {
						typ, local := baseTypeName(f.Type)
						if len(f.Names) == 0 && local {
							src.embeds[ts.Name.Name] = append(src.embeds[ts.Name.Name], typ)
						}
						for _, n := range f.Names {
							src.fields[ts.Name.Name][n.Name] = typ
						}
					}
				}
			}
		}
	}
	return src
}

// method finds a method on typeName or on a type it embeds.
func (s *lockSource) method(typeName, name string) *ast.FuncDecl {
	seen := make(map[string]bool)
	var find func(string) *ast.FuncDecl
	find = func(tn string) *ast.FuncDecl {
		if seen[tn] {
			return nil
		}
		seen[tn] = true
		if d := s.methods[tn][name]; d != nil {
			return d
		}
		for _, e := range s.embeds[tn] {
			if d := find(e); d != nil {
				return d
			}
		}
		return nil
	}
	return find(typeName)
}

// reaches reports whether fn, or anything it calls inside the package, makes
// a call hit accepts. Calls are followed by name: a method call follows every
// same-package method of that name. That over-approximates, which is the safe
// direction for a table whose job is to forbid.
func (s *lockSource) reaches(fn *ast.FuncDecl, hit func(owner *ast.FuncDecl, call *ast.CallExpr) bool) bool {
	visiting := make(map[*ast.FuncDecl]bool)
	var walk func(*ast.FuncDecl) bool
	walk = func(d *ast.FuncDecl) bool {
		if d == nil || d.Body == nil || visiting[d] {
			return false
		}
		visiting[d] = true
		found := false
		ast.Inspect(d.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if hit(d, call) {
				found = true
				return false
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if walk(s.funcs[f.Name]) {
					found = true
				}
			case *ast.SelectorExpr:
				if _, isPkg := f.X.(*ast.Ident); isPkg && s.funcs[f.Sel.Name] == nil && len(s.byName[f.Sel.Name]) == 0 {
					return true
				}
				for _, m := range s.byName[f.Sel.Name] {
					if walk(m) {
						found = true
						break
					}
				}
			}
			return !found
		})
		return found
	}
	return walk(fn)
}

// regionLockCall recognises the core's own lock: bufferRWLock's methods are
// the only ones with these names in the package. exclusive leaves out the
// shared acquisition.
func regionLockCall(exclusive bool) func(*ast.FuncDecl, *ast.CallExpr) bool {
	return func(_ *ast.FuncDecl, call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "lock", "tryLock":
			return true
		case "rLock":
			return !exclusive
		}
		return false
	}
}

// TestLockTablesMatchWhatTheSourcesDo derives, from the sources, which
// exported methods take the lock their type's borrowing accessor holds, and
// fails when a table says otherwise. A method that takes the lock and is not
// listed takesLock is the dangerous direction: R1 would let it be called
// inside its own borrow, where it deadlocks behind a queued writer. The other
// direction is reported too, because it means the table no longer describes
// the code.
func TestLockTablesMatchWhatTheSourcesDo(t *testing.T) {
	root := ".."
	if !declaresModule(filepath.Join(root, "go.mod"), secmemPkg) ||
		!declaresModule(filepath.Join(root, "secmem-crypto", "go.mod"), cryptoPkg) {
		t.Skip("the secmem and secmem-crypto sources are not next to this module; nothing to derive from")
	}
	core := parseLockSource(t, root, "secmem")
	crypto := parseLockSource(t, filepath.Join(root, "secmem-crypto"), "secmemcrypto")

	// Core: a method takes the lock when it reaches a bufferRWLock call.
	coreTakes := func(typeName, method string, exclusive bool) bool {
		return core.reaches(core.method(typeName, method), regionLockCall(exclusive))
	}
	// The names of core methods that take a lock, for the crypto side.
	coreLockNames := make(map[string]bool)
	for _, typeName := range []string{"SecureBuffer", "Secret", "ArenaSlot"} {
		for name := range methodLocks[secmemPkg+"."+typeName] {
			if coreTakes(typeName, name, false) {
				coreLockNames[name] = true
			}
		}
	}

	check := func(key, typeName string, table map[string]lockUse, takes func(method string) bool) {
		for _, name := range sortedKeys(table) {
			derived := takes(name)
			switch {
			case derived && table[name] != takesLock:
				t.Errorf("%s.%s reaches the lock in the sources but is listed lockFree: "+
					"called inside its own borrow it can deadlock, and the lint would allow it", key, name)
			case !derived && table[name] == takesLock:
				t.Errorf("%s.%s is listed takesLock but no path from it to the lock was found in the sources: "+
					"the table (or this derivation) no longer describes the code", key, name)
			}
		}
	}

	for _, key := range sortedKeys(methodLocks) {
		pkgPath, typeName := splitTypeKey(key)
		switch pkgPath {
		case secmemPkg:
			check(key, typeName, methodLocks[key], func(m string) bool { return coreTakes(typeName, m, false) })
		case cryptoPkg:
			// Crypto: a method takes the lock when it calls a lock-taking core
			// method on a buffer the key owns: a field of the receiver, or a
			// buffer handed down to a helper as a parameter.
			fields := crypto.fields[typeName]
			check(key, typeName, methodLocks[key], func(m string) bool {
				return crypto.reaches(crypto.method(typeName, m), func(owner *ast.FuncDecl, call *ast.CallExpr) bool {
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || !coreLockNames[sel.Sel.Name] {
						return false
					}
					switch x := sel.X.(type) {
					case *ast.SelectorExpr: // recv.field.Method(...)
						return strings.HasPrefix(fields[x.Sel.Name], "secmem.") ||
							ownedBufferField(crypto, x.Sel.Name)
					case *ast.Ident: // param.Method(...)
						return secmemParam(owner, x.Name)
					}
					return false
				})
			})
		default:
			t.Errorf("methodLocks key %q names neither library", key)
		}
	}

	// SecureArena: arenaLocks is about the EXCLUSIVE side, which is what a
	// slot callback (holding the shared side) deadlocks on.
	check(secmemPkg+".SecureArena", "SecureArena", arenaLocks, func(m string) bool {
		return coreTakes("SecureArena", m, true)
	})
}

// ownedBufferField reports whether any struct in the package has a field of
// this name whose type is a secmem type: a method reached by name may belong
// to a different key type than the one being checked.
func ownedBufferField(s *lockSource, field string) bool {
	for _, fields := range s.fields {
		if strings.HasPrefix(fields[field], "secmem.") {
			return true
		}
	}
	return false
}

// secmemParam reports whether name is a parameter of fn declared with a
// secmem type.
func secmemParam(fn *ast.FuncDecl, name string) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, p := range fn.Type.Params.List {
		typ, _ := baseTypeName(p.Type)
		if !strings.HasPrefix(typ, "secmem.") {
			continue
		}
		for _, n := range p.Names {
			if n.Name == name {
				return true
			}
		}
	}
	return false
}

// splitTypeKey splits "import/path.Type" at its last dot.
func splitTypeKey(key string) (pkgPath, typeName string) {
	i := strings.LastIndex(key, ".")
	return key[:i], key[i+1:]
}

// TestStubsMatchTheRealAPI keeps the testdata stubs, which every fixture
// compiles against, in step with the libraries. A stub that declares a method
// the library lacks lets a fixture pass for a call nobody can write; a
// library method missing from the stub cannot be put in a fixture at all.
// Checked for the classified types: same exported method names both ways,
// and the same parameter and result counts, a trailing variadic excepted
// (the stubs leave out option lists).
func TestStubsMatchTheRealAPI(t *testing.T) {
	root := ".."
	if !declaresModule(filepath.Join(root, "go.mod"), secmemPkg) ||
		!declaresModule(filepath.Join(root, "secmem-crypto", "go.mod"), cryptoPkg) {
		t.Skip("the secmem and secmem-crypto sources are not next to this module; nothing to compare the stubs against")
	}
	stubRoot := filepath.Join("testdata", "src", filepath.FromSlash(secmemPkg))
	pairs := []struct {
		pkgPath    string
		real, stub *sourcePackage
		realFuncs  map[string]*ast.FuncDecl
		stubFuncs  map[string]*ast.FuncDecl
	}{
		{
			pkgPath:   secmemPkg,
			real:      parseSourcePackage(t, root, "secmem"),
			stub:      parseSourcePackage(t, stubRoot, "secmem"),
			realFuncs: parseLockSource(t, root, "secmem").funcs,
			stubFuncs: parseLockSource(t, stubRoot, "secmem").funcs,
		},
		{
			pkgPath:   cryptoPkg,
			real:      parseSourcePackage(t, filepath.Join(root, "secmem-crypto"), "secmemcrypto"),
			stub:      parseSourcePackage(t, filepath.Join(stubRoot, "secmem-crypto"), "secmemcrypto"),
			realFuncs: parseLockSource(t, filepath.Join(root, "secmem-crypto"), "secmemcrypto").funcs,
			stubFuncs: parseLockSource(t, filepath.Join(stubRoot, "secmem-crypto"), "secmemcrypto").funcs,
		},
	}
	classified := make(map[string]bool)
	for key := range methodLocks {
		classified[key] = true
	}
	classified[secmemPkg+".SecureArena"] = true

	for _, p := range pairs {
		for _, typeName := range p.real.exportedTypes() {
			key := p.pkgPath + "." + typeName
			if !classified[key] {
				continue
			}
			realSet, stubSet := p.real.methodSet(t, typeName), p.stub.methodSet(t, typeName)
			for _, name := range sortedKeys(realSet) {
				if stubSet[name] == nil {
					t.Errorf("stub %s has no method %s, which the library exports", key, name)
					continue
				}
				if why := sameShape(realSet[name], stubSet[name]); why != "" {
					t.Errorf("stub %s.%s does not match the library: %s", key, name, why)
				}
			}
			for _, name := range sortedKeys(stubSet) {
				if realSet[name] == nil {
					t.Errorf("stub %s declares method %s, which the library does not have", key, name)
				}
			}
		}
		var names []string
		for name := range p.stubFuncs {
			if ast.IsExported(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			realFn := p.realFuncs[name]
			if realFn == nil {
				t.Errorf("stub %s declares func %s, which the library does not have", p.pkgPath, name)
				continue
			}
			if why := sameShape(realFn, p.stubFuncs[name]); why != "" {
				t.Errorf("stub %s.%s does not match the library: %s", p.pkgPath, name, why)
			}
		}
	}
}

// sameShape compares parameter and result counts, ignoring a trailing
// variadic parameter on either side. It returns "" when they agree.
func sameShape(realFn, stubFn *ast.FuncDecl) string {
	count := func(fl *ast.FieldList, dropVariadic bool) int {
		if fl == nil {
			return 0
		}
		n := 0
		for i, f := range fl.List {
			if _, variadic := f.Type.(*ast.Ellipsis); variadic && dropVariadic && i == len(fl.List)-1 {
				continue
			}
			if len(f.Names) == 0 {
				n++
			} else {
				n += len(f.Names)
			}
		}
		return n
	}
	if r, s := count(realFn.Type.Params, true), count(stubFn.Type.Params, true); r != s {
		return "the library takes " + itoa(r) + " parameters (variadic options aside), the stub " + itoa(s)
	}
	if r, s := count(realFn.Type.Results, false), count(stubFn.Type.Results, false); r != s {
		return "the library returns " + itoa(r) + " values, the stub " + itoa(s)
	}
	return ""
}

func itoa(n int) string {
	const digits = "0123456789"
	if n < 10 {
		return digits[n : n+1]
	}
	return itoa(n/10) + digits[n%10:n%10+1]
}
