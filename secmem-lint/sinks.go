package secmemlint

import (
	"go/ast"
	"go/types"
)

// The sink tables. All three are data: adding a sink is adding a line.
//
//   - funcSinks: package-level functions, keyed "import/path.Func".
//   - methodSinkSpecs: methods matched by the RECEIVER's named type, keyed
//     "import/path.Type" + method. The receiver must resolve to one of the
//     listed named types; an io.Writer, io.Reader or net.Conn interface value is
//     deliberately absent — writing a secret to a connection is the egress the
//     program exists for, and the analyzer has no way to tell a socket from a
//     bytes.Buffer behind the interface. Name the concrete type to be told.
//   - aliasFuncs: constructors whose result holds a reference to (or a copy of)
//     the argument without being a leak in themselves — bytes.NewReader(b) fed
//     straight to io.Copy stays inside the lease. Their result is tainted and
//     reported where it escapes.

const (
	reasonHeapCopy = "it copies the secret to the heap outside the buffer lifecycle"
	reasonHeapStr  = "it copies the secret to a heap string"
	reasonLog      = "it logs the secret"
	reasonFIPS     = "the FIPS cache panics on off-heap memory — use secmem-crypto's Ed25519Signer"
	reasonKeyCopy  = "it copies the key into heap memory it never wipes"
	reasonKDF      = "it copies the secret into heap working state — use secmem-crypto's *Into KDFs"
	reasonDecode   = "it decodes the secret into heap values"
)

// funcSinks maps "import/path.Func" to the reason passing borrowed secret bytes
// to it is dangerous. Where secmem offers a safe alternative, the reason names
// it.
var funcSinks = map[string]string{ //nolint:gochecknoglobals // immutable lookup table.
	// crypto: the Go 1.26+ FIPS cache builds a weak reference to the input,
	// which panics on mmap'd (off-heap) SecureBuffer memory.
	"crypto/ed25519.Sign":           "the FIPS cache panics on off-heap memory — sign in place with secmem-crypto's Ed25519Signer",
	"crypto/ed25519.NewKeyFromSeed": reasonFIPS,
	"crypto/hmac.New":               "it keeps a live reference to the key outside secure memory",

	// crypto: ciphers and key parsers copy the key into heap state.
	"crypto/aes.NewCipher":                                  reasonKeyCopy,
	"crypto/des.NewCipher":                                  reasonKeyCopy,
	"crypto/des.NewTripleDESCipher":                         reasonKeyCopy,
	"crypto/rc4.NewCipher":                                  reasonKeyCopy,
	"golang.org/x/crypto/chacha20poly1305.New":              reasonKeyCopy,
	"golang.org/x/crypto/chacha20poly1305.NewX":             reasonKeyCopy,
	"golang.org/x/crypto/chacha20.NewUnauthenticatedCipher": reasonKeyCopy,
	"crypto/x509.ParsePKCS8PrivateKey":                      reasonKeyCopy,
	"crypto/x509.ParsePKCS1PrivateKey":                      reasonKeyCopy,
	"crypto/x509.ParseECPrivateKey":                         reasonKeyCopy,
	"golang.org/x/crypto/ssh.ParseRawPrivateKey":            reasonKeyCopy,
	"golang.org/x/crypto/ssh.ParsePrivateKey":               reasonKeyCopy,
	"golang.org/x/crypto/ssh.ParsePrivateKeyWithPassphrase": reasonKeyCopy,

	// crypto: KDFs hold the password and their working state on the heap.
	"crypto/hkdf.Key":                                   reasonKDF,
	"crypto/hkdf.Extract":                               reasonKDF,
	"crypto/hkdf.Expand":                                reasonKDF,
	"crypto/pbkdf2.Key":                                 reasonKDF,
	"golang.org/x/crypto/hkdf.New":                      reasonKDF,
	"golang.org/x/crypto/hkdf.Extract":                  reasonKDF,
	"golang.org/x/crypto/hkdf.Expand":                   reasonKDF,
	"golang.org/x/crypto/pbkdf2.Key":                    reasonKDF,
	"golang.org/x/crypto/scrypt.Key":                    reasonKDF,
	"golang.org/x/crypto/argon2.Key":                    reasonKDF,
	"golang.org/x/crypto/argon2.IDKey":                  reasonKDF,
	"golang.org/x/crypto/bcrypt.GenerateFromPassword":   reasonKDF,
	"golang.org/x/crypto/bcrypt.CompareHashAndPassword": reasonKDF,

	// heap copies outside the buffer lifecycle.
	"bytes.Clone":                 reasonHeapCopy,
	"bytes.Join":                  reasonHeapCopy,
	"bytes.Repeat":                reasonHeapCopy,
	"slices.Clone":                reasonHeapCopy,
	"slices.Concat":               reasonHeapCopy,
	"slices.Repeat":               reasonHeapCopy,
	"encoding/json.Marshal":       reasonHeapCopy,
	"encoding/json.MarshalIndent": reasonHeapCopy,
	"encoding/json.Unmarshal":     reasonDecode,
	"encoding/json.NewDecoder":    reasonDecode,
	"encoding/xml.Unmarshal":      reasonDecode,
	"encoding/gob.NewDecoder":     reasonDecode,
	"encoding/hex.EncodeToString": reasonHeapStr,
	"encoding/hex.Encode":         "it copies the secret to a heap destination",
	"encoding/hex.Dump":           reasonHeapStr,
	"encoding/hex.AppendEncode":   "it appends the secret to an escaping byte slice",
	"encoding/pem.EncodeToMemory": reasonHeapCopy,
	"os.WriteFile":                "it writes the secret to a file",

	// fmt: formats or prints the secret into a heap string or an io.Writer.
	"fmt.Sprintf":  "it formats the secret into a heap string",
	"fmt.Sprint":   "it formats the secret into a heap string",
	"fmt.Sprintln": "it formats the secret into a heap string",
	"fmt.Errorf":   "it formats the secret into a heap error string",
	"fmt.Fprintf":  "it writes the secret to an io.Writer",
	"fmt.Fprint":   "it writes the secret to an io.Writer",
	"fmt.Fprintln": "it writes the secret to an io.Writer",
	"fmt.Printf":   "it prints the secret to stdout",
	"fmt.Print":    "it prints the secret to stdout",
	"fmt.Println":  "it prints the secret to stdout",
	"fmt.Append":   "it appends the secret to an escaping byte slice",
	"fmt.Appendf":  "it appends the secret to an escaping byte slice",
	"fmt.Appendln": "it appends the secret to an escaping byte slice",

	// log / log/slog: never log secret material. slog's attribute
	// constructors are sinks in their own right, so slog.Info("m",
	// slog.Any("k", b)) is caught at the Any.
	"log.Printf":            reasonLog,
	"log.Println":           reasonLog,
	"log.Print":             reasonLog,
	"log.Fatalf":            reasonLog,
	"log.Fatal":             reasonLog,
	"log.Fatalln":           reasonLog,
	"log.Panicf":            reasonLog,
	"log.Panic":             reasonLog,
	"log.Panicln":           reasonLog,
	"log/slog.Info":         reasonLog,
	"log/slog.Warn":         reasonLog,
	"log/slog.Error":        reasonLog,
	"log/slog.Debug":        reasonLog,
	"log/slog.InfoContext":  reasonLog,
	"log/slog.WarnContext":  reasonLog,
	"log/slog.ErrorContext": reasonLog,
	"log/slog.DebugContext": reasonLog,
	"log/slog.Log":          reasonLog,
	"log/slog.LogAttrs":     reasonLog,
	"log/slog.Any":          reasonLog,
	"log/slog.String":       reasonLog,
	"log/slog.Group":        reasonLog,
	"log/slog.AnyValue":     reasonLog,
	"log/slog.StringValue":  reasonLog,
}

// methodSinkSpec lists sink methods on one named receiver type.
type methodSinkSpec struct {
	pkg, typ string
	methods  []string
	reason   string
}

var (
	logMethods = []string{ //nolint:gochecknoglobals // immutable.
		"Print", "Printf", "Println", "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln", "Output",
	}
	slogMethods = []string{ //nolint:gochecknoglobals // immutable.
		"Debug", "Info", "Warn", "Error", "DebugContext", "InfoContext", "WarnContext", "ErrorContext",
		"Log", "LogAttrs", "With",
	}
	testLogMethods = []string{ //nolint:gochecknoglobals // immutable.
		"Log", "Logf", "Error", "Errorf", "Fatal", "Fatalf", "Skip", "Skipf",
	}
	writeMethods  = []string{"Write", "WriteString"}                     //nolint:gochecknoglobals // immutable.
	encodeMethods = []string{"EncodeToString", "Encode", "AppendEncode"} //nolint:gochecknoglobals // immutable.
)

var methodSinkSpecs = []methodSinkSpec{ //nolint:gochecknoglobals // immutable lookup table.
	{"log", "Logger", logMethods, reasonLog},
	{"log/slog", "Logger", slogMethods, reasonLog},
	{"testing", "T", testLogMethods, "it logs the secret in the test output"},
	{"testing", "B", testLogMethods, "it logs the secret in the test output"},
	{"testing", "F", testLogMethods, "it logs the secret in the test output"},
	{"testing", "TB", testLogMethods, "it logs the secret in the test output"},
	{"bytes", "Buffer", writeMethods, "it copies the secret into a heap buffer that is never wiped"},
	{"strings", "Builder", writeMethods, "it copies the secret into a heap buffer that is never wiped"},
	{"bufio", "Writer", writeMethods, "it copies the secret into the writer's heap buffer"},
	{"os", "File", []string{"Write", "WriteString", "WriteAt"}, "it writes the secret to a file"},
	{"encoding/base64", "Encoding", encodeMethods, reasonHeapCopy},
	{"encoding/base32", "Encoding", encodeMethods, reasonHeapCopy},
	{"crypto/ecdh", "Curve", []string{"NewPrivateKey"}, reasonKeyCopy},
}

// methodSinks is methodSinkSpecs flattened to "import/path.Type.Method".
var methodSinks = func() map[string]string { //nolint:gochecknoglobals // immutable lookup table.
	m := make(map[string]string)
	for _, spec := range methodSinkSpecs {
		for _, name := range spec.methods {
			m[spec.pkg+"."+spec.typ+"."+name] = spec.reason
		}
	}
	return m
}()

// aliasFuncs are the constructors whose result retains its argument.
var aliasFuncs = map[string]bool{ //nolint:gochecknoglobals // immutable lookup table.
	"bytes.NewReader":   true,
	"bytes.NewBuffer":   true,
	"strings.NewReader": true,
	"bufio.NewReader":   true,
	"io.NopCloser":      true,
	"reflect.ValueOf":   true,
}

// sinkFor resolves a call to a sink, returning its display name and the reason
// it is dangerous, or "" if it is not one.
func (c *checker) sinkFor(call *ast.CallExpr) (name, reason string) {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	if key, ok := c.packageFuncKey(sel); ok {
		return key, funcSinks[key]
	}
	if _, ok := c.pass.TypesInfo.Selections[sel]; !ok {
		return "", ""
	}
	recv := namedTypeKey(c.pass.TypesInfo.TypeOf(sel.X))
	if recv == "" {
		return "", ""
	}
	key := recv + "." + sel.Sel.Name
	return key, methodSinks[key]
}

func (c *checker) isAliasFunc(call *ast.CallExpr) bool {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	key, ok := c.packageFuncKey(sel)
	return ok && aliasFuncs[key]
}

// packageFuncKey returns "import/path.Func" for a package-qualified selector.
func (c *checker) packageFuncKey(sel *ast.SelectorExpr) (string, bool) {
	x, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	pkg, ok := c.pass.TypesInfo.Uses[x].(*types.PkgName)
	if !ok {
		return "", false
	}
	return pkg.Imported().Path() + "." + sel.Sel.Name, true
}
