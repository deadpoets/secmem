package httpauth_test

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/httpauth"
)

// The intended use: the token lives in a SecureBuffer for the client's
// lifetime and becomes a string only for the duration of each request.
// WithHosts names the API so a redirect elsewhere never carries the
// credential.
func ExampleNewBearer() {
	raw := []byte("read-this-from-a-file-or-a-vault, never a literal")
	tok, err := secmem.NewBuffer(raw) // raw is wiped after the copy
	if err != nil {
		fmt.Println("alloc:", err)
		return
	}
	defer func() { _ = tok.Destroy() }()

	t, err := httpauth.NewBearer(tok, httpauth.WithHosts("api.example.com"))
	if err != nil {
		fmt.Println("config:", err)
		return
	}
	client := &http.Client{Transport: t}
	// Every https request to api.example.com now carries
	// "Authorization: Bearer …"; a request to any other host goes through
	// untouched.
	resp, err := client.Get("https://api.example.com/v1/me")
	if err != nil {
		fmt.Println("request:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

// Entries may pin a scheme. Here the production API is https only, and a
// local development server is opted in to cleartext by name; no other host
// receives the credential, and no other host may use http.
func ExampleWithHosts() {
	tok, err := secmem.NewBuffer([]byte("token"))
	if err != nil {
		fmt.Println("alloc:", err)
		return
	}
	defer func() { _ = tok.Destroy() }()

	_, err = httpauth.NewBearer(tok, httpauth.WithHosts(
		"https://api.example.com",
		"http://localhost:8080",
	))
	fmt.Println("both hosts:", err)

	// Forgetting the host decision is an error, not an every-host transport.
	_, err = httpauth.NewBearer(tok)
	fmt.Println("no hosts:", errors.Is(err, httpauth.ErrNoHosts))
	// Output:
	// both hosts: <nil>
	// no hosts: true
}
