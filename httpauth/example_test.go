package httpauth_test

import (
	"fmt"
	"net/http"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/httpauth"
)

// The intended use: the token lives in a SecureBuffer for the client's
// lifetime and becomes a string only for the duration of each request. Hosts
// names the API so a redirect elsewhere never carries the credential.
func ExampleNewBearer() {
	raw := []byte("read-this-from-a-file-or-a-vault, never a literal")
	tok, err := secmem.NewBuffer(raw) // raw is wiped after the copy
	if err != nil {
		fmt.Println("alloc:", err)
		return
	}
	defer func() { _ = tok.Destroy() }()

	client := &http.Client{
		Transport: httpauth.NewBearer(tok, nil, "api.example.com"),
	}
	// Every request to api.example.com now carries "Authorization: Bearer …";
	// a request to any other host goes through untouched.
	resp, err := client.Get("https://api.example.com/v1/me")
	if err != nil {
		fmt.Println("request:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}
