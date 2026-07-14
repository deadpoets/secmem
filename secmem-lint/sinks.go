package secmemlint

// sinks maps "import/path.Func" to the reason passing borrowed secret bytes to
// it is dangerous. Every entry is a standard-library function (no third-party
// names); where secmem offers a safe alternative, the reason names it.
var sinks = map[string]string{ //nolint:gochecknoglobals // immutable lookup table.
	// crypto: the Go 1.26+ FIPS cache builds a weak reference to the input,
	// which panics on mmap'd (off-heap) SecureBuffer memory.
	"crypto/ed25519.Sign":           "the FIPS cache panics on off-heap memory — sign in place with secmem-crypto's Ed25519Signer",
	"crypto/ed25519.NewKeyFromSeed": "the FIPS cache panics on off-heap memory — use secmem-crypto's Ed25519Signer",
	"crypto/hmac.New":               "it keeps a live reference to the key outside secure memory",

	// heap copies outside the buffer lifecycle.
	"bytes.Clone":                 "it copies the secret to the heap outside the buffer lifecycle",
	"slices.Clone":                "it copies the secret to the heap outside the buffer lifecycle",
	"encoding/json.Marshal":       "it copies the secret to the heap outside the buffer lifecycle",
	"encoding/json.MarshalIndent": "it copies the secret to the heap outside the buffer lifecycle",
	"encoding/hex.EncodeToString": "it copies the secret to a heap string",
	"encoding/hex.Encode":         "it copies the secret to a heap destination",

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

	// log / log/slog: never log secret material.
	"log.Printf":            "it logs the secret",
	"log.Println":           "it logs the secret",
	"log.Print":             "it logs the secret",
	"log.Fatalf":            "it logs the secret",
	"log.Fatal":             "it logs the secret",
	"log.Fatalln":           "it logs the secret",
	"log.Panicf":            "it logs the secret",
	"log.Panic":             "it logs the secret",
	"log/slog.Info":         "it logs the secret",
	"log/slog.Warn":         "it logs the secret",
	"log/slog.Error":        "it logs the secret",
	"log/slog.Debug":        "it logs the secret",
	"log/slog.InfoContext":  "it logs the secret",
	"log/slog.WarnContext":  "it logs the secret",
	"log/slog.ErrorContext": "it logs the secret",
	"log/slog.DebugContext": "it logs the secret",
}
