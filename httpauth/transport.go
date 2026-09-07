// Package httpauth injects a credential header into HTTP requests from a
// [secmem.SecureBuffer], so an HTTP client never holds the token as a
// long-lived Go string.
//
// Every cloud SDK and API client takes its token as a string and keeps it for
// the client's lifetime. That string sits on the garbage-collected heap —
// unlocked, unwiped, movable, in every core dump — for as long as the client
// lives, which is usually the life of the process. A [Transport] keeps the
// credential in a SecureBuffer instead and builds the header value per
// request, which bounds the string's lifetime to one request.
//
// HONESTY — the residual, stated plainly:
//
// The per-request string copy is unavoidable. net/http takes header values
// as strings, Go strings are immutable, and nothing can wipe one: the copy
// lives until the collector reclaims it, and the collector does not zero
// what it reclaims. What this package does about it is narrow and specific.
// The value is built inside a [secmem.ScrubErr] window, so on a
// GOEXPERIMENT=runtimesecret build (linux/amd64, linux/arm64) the runtime
// erases the allocation once it is unreachable; on every other build the
// window only scrubs the stack frame, and the string is an ordinary heap
// object. Every scratch slice the value was assembled from is wiped with
// [secmem.SecureWipe] before the window closes. After the request completes
// the header is deleted from the request the transport sent, so the only
// reference to the value is dropped as early as this package can drop it.
// Out of reach entirely: the bytes the underlying transport wrote to the
// connection's write buffer and to any TLS record buffer, and anything a
// Base transport that logs or caches requests keeps for itself.
//
// The redirect footgun: this transport sits BELOW [net/http.Client]. The
// Client's rule of dropping Authorization on a cross-domain redirect applies
// to headers on the request it was handed, not to what a RoundTripper injects
// on each hop — the Client builds the redirected request without the header,
// hands it back down, and this transport injects again. Set [Transport.Hosts]
// so injection happens only for the hosts the credential is meant for; leave
// it empty only when the client never follows redirects or the API never
// issues one.
//
// The package is stdlib + secmem only. A Transport is safe for concurrent
// use once constructed; its fields must not be modified while requests are
// in flight.
package httpauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/deadpoets/secmem"
)

// ErrNoToken is returned by [Transport.RoundTrip] when the Transport has no
// Token to inject.
var ErrNoToken = errors.New("httpauth: no token")

// ErrNilRequest is returned by [Transport.RoundTrip] for a nil request.
var ErrNilRequest = errors.New("httpauth: nil request")

// ErrBasicUsername is returned by [Transport.RoundTrip] when a Transport built
// with [NewBasic] has a username containing ':'. RFC 7617 forbids it: the
// server splits user-pass at the first colon, so such a name cannot be
// transmitted correctly and is refused rather than sent wrong.
var ErrBasicUsername = errors.New("httpauth: basic username must not contain ':'")

// defaultHeader is the header set when [Transport.Header] is empty.
const defaultHeader = "Authorization"

// Transport is an [http.RoundTripper] that sets a credential header on each
// request from a [secmem.SecureBuffer]. Construct one with [NewBearer],
// [NewHeader] or [NewBasic], or as a literal for a plain header (a literal
// with Prefix "Basic " sets that prefix verbatim and does no base64; only
// [NewBasic] encodes).
//
// The caller's request is never modified: RoundTrip clones it, sets the
// header on the clone, and deletes the header from the clone once the Base
// transport returns.
type Transport struct {
	// Base performs the request; nil means http.DefaultTransport.
	Base http.RoundTripper

	// Header is the header to set (default "Authorization").
	Header string

	// Prefix precedes the token in the header value, e.g. "Bearer ".
	Prefix string

	// Token holds the credential. The Transport does not own it: the caller
	// destroys it, after which RoundTrip fails with an error wrapping
	// secmem.ErrDestroyed. A sealed Token fails with an error wrapping
	// secmem.ErrSealed until it is unsealed.
	Token *secmem.SecureBuffer

	// Hosts restricts injection to requests whose URL host (req.URL.Host,
	// compared case-insensitively, port included as written) is listed. Empty
	// means every request through this transport — only right when the client
	// never follows redirects or the API never redirects: this transport sits
	// BELOW http.Client, so the Client's own rule of dropping Authorization on
	// a cross-domain redirect does not apply to what is injected here.
	Hosts []string

	// basic is set by NewBasic: the value is base64(basicUser + ":" + Token)
	// with a "Basic " prefix, rather than Prefix + Token.
	basic     bool
	basicUser string
}

// NewBearer returns a Transport that sets "Authorization: Bearer <token>".
// base nil means http.DefaultTransport; hosts is [Transport.Hosts].
func NewBearer(token *secmem.SecureBuffer, base http.RoundTripper, hosts ...string) *Transport {
	return NewHeader(defaultHeader, "Bearer ", token, base, hosts...)
}

// NewHeader returns a Transport that sets header to prefix followed by the
// token, e.g. NewHeader("X-API-Key", "", key, nil) for an API-key header.
// An empty header means "Authorization". base nil means
// http.DefaultTransport; hosts is [Transport.Hosts].
func NewHeader(header, prefix string, token *secmem.SecureBuffer, base http.RoundTripper, hosts ...string) *Transport {
	return &Transport{
		Base:   base,
		Header: header,
		Prefix: prefix,
		Token:  token,
		Hosts:  hosts,
	}
}

// NewBasic returns a Transport that sets
// "Authorization: Basic base64(username:password)" (RFC 7617). username must
// not contain ':' — RoundTrip returns [ErrBasicUsername] if it does. base nil
// means http.DefaultTransport; hosts is [Transport.Hosts].
//
// The username is held as a plain string: it is the identifier, not the
// secret. The password never becomes a string on its own; it is copied into
// one wiped scratch slice alongside the username, encoded into a second, and
// only the finished header value is a string.
func NewBasic(username string, password *secmem.SecureBuffer, base http.RoundTripper, hosts ...string) *Transport {
	return &Transport{
		Base:      base,
		Header:    defaultHeader,
		Token:     password,
		Hosts:     hosts,
		basic:     true,
		basicUser: username,
	}
}

// RoundTrip implements [http.RoundTripper]. It clones req, sets the credential
// header on the clone when the host filter admits it, and forwards the clone
// to Base. The header is deleted from the clone (which the response's Request
// field points at) once Base returns, whether or not it succeeded.
//
// A request whose host is excluded by [Transport.Hosts] is forwarded to Base
// unchanged and the Token is not touched.
//
// Errors: [ErrNilRequest]; [ErrNoToken] for a nil Token; an error wrapping
// [secmem.ErrDestroyed] or [secmem.ErrSealed] for a Token in that state;
// [ErrBasicUsername]; otherwise whatever Base returns.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return nil, errors.New("httpauth: RoundTrip on a nil *Transport")
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if !t.admits(req) {
		return t.base().RoundTrip(req)
	}
	if t.Token == nil {
		return nil, ErrNoToken
	}

	// Never mutate the caller's request: the RoundTripper contract forbids it,
	// and it is also what keeps the credential out of the request the caller
	// holds on to. Clone deep-copies the Header map.
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}

	// The value is built inside a scrub window and assigned to a variable
	// declared outside the closure — the result-survival rule: a value
	// produced inside the window survives it only while something outside
	// still references it. Nothing else happens in the window; in particular
	// Base.RoundTrip does not run inside it, because network I/O in a Scrub
	// window pins the thread and holds the preemption signal blocked for the
	// duration of the round trip.
	var value string
	var err error
	if t.basic {
		value, err = t.basicValue()
	} else {
		value, err = t.headerValue()
	}
	if err != nil {
		return nil, err
	}
	name := t.header()
	clone.Header.Set(name, value)

	resp, rerr := t.base().RoundTrip(clone)

	// Drop the only reference this package holds to the value. Nothing can
	// wipe a Go string; the most that can be done is to make it unreachable
	// as early as possible, so the collector — and runtime/secret on a build
	// where it is active — can reclaim it. The response's Request field points
	// at the clone, so without this deletion the credential would stay
	// reachable for as long as the caller keeps the response.
	clone.Header.Del(name)
	return resp, rerr
}

// admits reports whether req's host passes the Hosts filter. An empty filter
// admits everything.
func (t *Transport) admits(req *http.Request) bool {
	if len(t.Hosts) == 0 {
		return true
	}
	if req.URL == nil {
		return false
	}
	for _, h := range t.Hosts {
		if strings.EqualFold(req.URL.Host, h) {
			return true
		}
	}
	return false
}

// base returns the RoundTripper that performs requests.
func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return http.DefaultTransport
	}
	return t.Base
}

// header returns the header name to set.
func (t *Transport) header() string {
	if t.Header == "" {
		return defaultHeader
	}
	return t.Header
}

// headerValue builds Prefix + token inside a scrub window.
func (t *Transport) headerValue() (string, error) {
	var value string
	err := secmem.ScrubErr(func() error {
		n := t.Token.Len()
		buf := make([]byte, len(t.Prefix)+n)
		// Deferred so the scratch is wiped on the error paths too.
		defer secmem.SecureWipe(buf)
		copy(buf, t.Prefix)
		if err := t.copyToken(buf[len(t.Prefix):], n); err != nil {
			return err
		}
		value = string(buf)
		return nil
	})
	if err != nil {
		return "", err
	}
	return value, nil
}

// basicValue builds "Basic " + base64(user:password) inside a scrub window.
// user:password is assembled in one scratch slice and encoded into a second
// with Encode rather than EncodeToString, which would make a second heap
// string; both scratches are wiped.
func (t *Transport) basicValue() (string, error) {
	if strings.Contains(t.basicUser, ":") {
		return "", ErrBasicUsername
	}
	const prefix = "Basic "
	var value string
	err := secmem.ScrubErr(func() error {
		n := t.Token.Len()
		raw := make([]byte, len(t.basicUser)+1+n)
		defer secmem.SecureWipe(raw)
		copy(raw, t.basicUser)
		raw[len(t.basicUser)] = ':'
		if err := t.copyToken(raw[len(t.basicUser)+1:], n); err != nil {
			return err
		}
		enc := make([]byte, len(prefix)+base64.StdEncoding.EncodedLen(len(raw)))
		defer secmem.SecureWipe(enc)
		copy(enc, prefix)
		base64.StdEncoding.Encode(enc[len(prefix):], raw)
		value = string(enc)
		return nil
	})
	if err != nil {
		return "", err
	}
	return value, nil
}

// copyToken copies the whole token into dst, which is exactly n = Token.Len()
// bytes as measured before the copy. CopyOut reports the buffer's own state:
// secmem.ErrDestroyed or secmem.ErrSealed, wrapped here so errors.Is finds
// them. A short copy means the buffer was truncated between the length read
// and the copy, and is refused rather than sent as a shorter credential.
func (t *Transport) copyToken(dst []byte, n int) error {
	if n == 0 {
		// Len is 0 for a destroyed buffer and never for a live one (the
		// constructors refuse empty input). Ask CopyOut anyway so the error
		// names the real state rather than guessing at it.
		if _, err := t.Token.CopyOut(dst, 0); err != nil {
			return fmt.Errorf("httpauth: reading token: %w", err)
		}
		return errors.New("httpauth: token is empty")
	}
	got, err := t.Token.CopyOut(dst, 0)
	if err != nil {
		return fmt.Errorf("httpauth: reading token: %w", err)
	}
	if got != n {
		return fmt.Errorf("httpauth: token changed length during read (%d of %d bytes)", got, n)
	}
	return nil
}
