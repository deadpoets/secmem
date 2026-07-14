// Command secmem-lint is a go vet tool that flags secret material escaping a
// secmem borrowing closure.
//
//	go vet -vettool=$(command -v secmem-lint) ./...
package main

import (
	secmemlint "github.com/deadpoets/secmem/secmem-lint"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(secmemlint.Analyzer)
}
