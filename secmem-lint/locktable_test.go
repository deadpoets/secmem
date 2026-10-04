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

// TestLockTablesCoverSiblingSources keeps methodLocks, arenaLocks and
// borrowMethods in step with the libraries they describe. It reads the core
// and secmem-crypto sources next to this module and fails for:
//
//   - an exported method on a type with a borrowing accessor that
//     methodLocks does not classify (as takesLock or lockFree);
//   - an exported SecureArena method arenaLocks does not classify;
//   - a method taking a func([]byte ...) closure that borrowMethods does not
//     name, so its closure would go unchecked;
//   - a table entry naming a type or method the sources no longer have.
//
// The sources are parsed, not imported: this module depends on x/tools only,
// and parsing sees the methods of every platform's files at once. A copy of
// the module without its siblings — one fetched from the module proxy — has
// nothing to compare against and skips.
func TestLockTablesCoverSiblingSources(t *testing.T) {
	root := ".."
	if !declaresModule(filepath.Join(root, "go.mod"), secmemPkg) ||
		!declaresModule(filepath.Join(root, "secmem-crypto", "go.mod"), cryptoPkg) {
		t.Skip("the secmem and secmem-crypto sources are not next to this module; nothing to compare the tables against")
	}
	sources := map[string]*sourcePackage{
		secmemPkg: parseSourcePackage(t, root, "secmem"),
		cryptoPkg: parseSourcePackage(t, filepath.Join(root, "secmem-crypto"), "secmemcrypto"),
	}

	seen := make(map[string]bool) // methodLocks keys found in the sources
	for _, pkgPath := range []string{secmemPkg, cryptoPkg} {
		src := sources[pkgPath]
		for _, typeName := range src.exportedTypes() {
			methods := src.methodSet(t, typeName)
			borrowing := false
			for _, name := range sortedKeys(methods) {
				if !takesByteClosure(methods[name]) {
					continue
				}
				borrowing = true
				if !borrowMethods[pkgPath][name] {
					t.Errorf("%s.%s.%s takes a func([]byte) closure but is not in borrowMethods: its closure is not checked",
						pkgPath, typeName, name)
				}
			}
			if !borrowing {
				continue
			}
			key := pkgPath + "." + typeName
			seen[key] = true
			table, ok := methodLocks[key]
			if !ok {
				t.Errorf("%s has a borrowing accessor but no methodLocks entry", key)
				continue
			}
			for _, name := range sortedKeys(methods) {
				if table[name] == 0 {
					t.Errorf("%s.%s is not classified in methodLocks: read it and list it as takesLock or lockFree", key, name)
				}
			}
			for _, name := range sortedKeys(table) {
				if methods[name] == nil {
					t.Errorf("methodLocks lists %s.%s, which the sources do not declare", key, name)
				}
			}
		}
	}
	for _, key := range sortedKeys(methodLocks) {
		if !seen[key] {
			t.Errorf("methodLocks has an entry for %s, which is not an exported type with a borrowing accessor in the sources", key)
		}
	}

	arena := sources[secmemPkg].methodSet(t, "SecureArena")
	if len(arena) == 0 {
		t.Errorf("%s.SecureArena has no exported methods in the sources", secmemPkg)
	}
	for _, name := range sortedKeys(arena) {
		if arenaLocks[name] == 0 {
			t.Errorf("%s.SecureArena.%s is not classified in arenaLocks: read it and list it as takesLock or lockFree", secmemPkg, name)
		}
	}
	for _, name := range sortedKeys(arenaLocks) {
		if arena[name] == nil {
			t.Errorf("arenaLocks lists SecureArena.%s, which the sources do not declare", name)
		}
	}
}

// declaresModule reports whether the go.mod at path exists and declares the
// module modPath.
func declaresModule(path, modPath string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`) == modPath
		}
	}
	return false
}

// sourcePackage is the method-level shape of one package's non-test sources.
type sourcePackage struct {
	types    map[string]bool                     // declared type names
	methods  map[string]map[string]*ast.FuncDecl // type → exported method → declaration
	embedded map[string][]string                 // struct type → embedded types of the same package
	foreign  map[string][]string                 // struct type → embedded types of other packages
}

// parseSourcePackage parses every non-test file of package pkgName in dir,
// whatever its build constraints.
func parseSourcePackage(t *testing.T, dir, pkgName string) *sourcePackage {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	src := &sourcePackage{
		types:    make(map[string]bool),
		methods:  make(map[string]map[string]*ast.FuncDecl),
		embedded: make(map[string][]string),
		foreign:  make(map[string][]string),
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
				src.addMethod(d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						src.addType(ts)
					}
				}
			}
		}
	}
	if len(src.types) == 0 {
		t.Fatalf("no package %s sources in %s", pkgName, dir)
	}
	return src
}

func (p *sourcePackage) addMethod(d *ast.FuncDecl) {
	if d.Recv == nil || len(d.Recv.List) != 1 || !d.Name.IsExported() {
		return
	}
	recv, _ := baseTypeName(d.Recv.List[0].Type)
	if recv == "" {
		return
	}
	if p.methods[recv] == nil {
		p.methods[recv] = make(map[string]*ast.FuncDecl)
	}
	p.methods[recv][d.Name.Name] = d
}

func (p *sourcePackage) addType(ts *ast.TypeSpec) {
	p.types[ts.Name.Name] = true
	st, ok := ts.Type.(*ast.StructType)
	if !ok {
		return
	}
	for _, field := range st.Fields.List {
		if len(field.Names) != 0 {
			continue
		}
		name, local := baseTypeName(field.Type)
		if local {
			p.embedded[ts.Name.Name] = append(p.embedded[ts.Name.Name], name)
		} else {
			p.foreign[ts.Name.Name] = append(p.foreign[ts.Name.Name], name)
		}
	}
}

// baseTypeName names the type a receiver or embedded field is declared with,
// through a pointer and type arguments. local is false for a type qualified
// by another package, whose name comes back as "pkg.Type".
func baseTypeName(expr ast.Expr) (name string, local bool) {
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.Ident:
			return e.Name, true
		case *ast.SelectorExpr:
			if pkg, ok := e.X.(*ast.Ident); ok {
				return pkg.Name + "." + e.Sel.Name, false
			}
			return "", false
		default:
			return "", false
		}
	}
}

func (p *sourcePackage) exportedTypes() []string {
	var names []string
	for name := range p.types {
		if ast.IsExported(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// methodSet returns the exported methods callable on a value of the named
// type: its own and those promoted from the types it embeds. A type embedded
// from another package cannot be read here, so it is an error rather than a
// silent gap.
func (p *sourcePackage) methodSet(t *testing.T, typeName string) map[string]*ast.FuncDecl {
	t.Helper()
	set := make(map[string]*ast.FuncDecl)
	visited := make(map[string]bool)
	var walk func(name string)
	walk = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		for method, decl := range p.methods[name] {
			if set[method] == nil {
				set[method] = decl
			}
		}
		for _, f := range p.foreign[name] {
			t.Errorf("%s embeds %s from another package; its promoted methods are not visible to this test — classify them by hand and teach the test about it", name, f)
		}
		for _, e := range p.embedded[name] {
			walk(e)
		}
	}
	walk(typeName)
	return set
}

// takesByteClosure reports whether a method has a parameter of func type
// that itself takes a []byte: the shape of a borrowing accessor.
func takesByteClosure(d *ast.FuncDecl) bool {
	for _, param := range d.Type.Params.List {
		fn, ok := param.Type.(*ast.FuncType)
		if !ok || fn.Params == nil {
			continue
		}
		for _, inner := range fn.Params.List {
			arr, ok := inner.Type.(*ast.ArrayType)
			if !ok || arr.Len != nil {
				continue
			}
			if elt, ok := arr.Elt.(*ast.Ident); ok && elt.Name == "byte" {
				return true
			}
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
