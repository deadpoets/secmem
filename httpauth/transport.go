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
//
// Out of reach entirely — copies net/http makes that this package can
// neither wipe nor drop:
//
//   - The bytes written to the connection's bufio.Writer and to the TLS
//     record buffer. Both are reused for the next request on the connection
//     and overwritten then, not before.
//   - HTTP/2 HPACK state. The bundled http2 client hands every header field
//     to the HPACK encoder without marking it Sensitive, so
//     "authorization: Bearer …" is INSERTED INTO THE CONNECTION'S DYNAMIC
//     TABLE (4 KB by default) and stays there until enough later fields
//     evict it — on a pooled connection that can be the life of the
//     process. The encoder's scratch buffer holds the encoded field until
//     the next request on that connection overwrites it. [ForceHTTP1]
//     configures a Base transport that never negotiates h2, for callers who
//     want the shorter lifetime more than they want multiplexing.
//   - The header-writer's pooled sorter. HTTP/1 header writing sorts the
//     Header map's key/value slices through a sync.Pool-backed sorter; the
//     []string holding the credential stays reachable from that pool entry
//     until the sorter is reused, which is the next header write on any
//     connection in the process.
//   - An [net/http/httptrace.ClientTrace] with WroteHeaderField set is handed
//     the value as a string, and keeps whatever it keeps.
//   - Anything a Base transport that logs or caches requests keeps for
//     itself.
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
// The downgrade footgun: a host filter is scheme-blind unless told
// otherwise, and a redirect from https://api.example.com to
// http://api.example.com passes it. The credential is therefore never
// injected into a request whose scheme is not https unless the caller opts
// in — with [Transport.AllowInsecureHTTP] for every host, or with an
// "http://host" entry in Hosts for one — and a cleartext request to an
// admitted host fails with [ErrInsecureScheme] rather than going out
// without the header, so the downgrade is visible instead of a puzzling 401.
//
// The package is stdlib + secmem only. A Transport is safe for concurrent
// use once constructed; its fields must not be modified while requests are
// in flight.
package httpauth

import (
	"crypto/tls"
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

// ErrInsecureScheme is returned by [Transport.RoundTrip] when the request is
// for a host the credential is meant for but its URL scheme is not https and
// nothing opted in to cleartext. The request is not sent.
var ErrInsecureScheme = errors.New("httpauth: refusing to send the credential over cleartext http (set AllowInsecureHTTP, or list the host as \"http://host\" to opt in)")

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
	//
	// An entry may carry a scheme. "https://api.example.com" admits only
	// https requests to that host; "http://localhost:8080" admits only
	// cleartext ones, and is the per-host opt-in for them. A bare
	// "api.example.com" admits https, and http only when AllowInsecureHTTP is
	// set. A request to a listed host whose scheme no entry admits fails with
	// ErrInsecureScheme; a request to an unlisted host is forwarded to Base
	// untouched.
	Hosts []string

	// AllowInsecureHTTP permits injecting the credential into a request whose
	// URL scheme is not https, for every host the filter admits. Off by
	// default: without it a plain http URL, or an https→http redirect on an
	// admitted host, fails with ErrInsecureScheme instead of sending the
	// token in cleartext. Prefer an "http://host" entry in Hosts, which opts
	// in one host rather than all of them.
	AllowInsecureHTTP bool

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

// ForceHTTP1 returns a copy of base — of http.DefaultTransport when base is
// nil — that negotiates HTTP/1.1 only, for use as [Transport.Base] by
// callers who want the credential kept out of HTTP/2's per-connection HPACK
// dynamic table (see the package doc). It clears ForceAttemptHTTP2, sets an
// empty TLSNextProto map (net/http's documented way to disable its bundled
// http2), and drops "h2" from the TLS config's advertised protocols so the
// server cannot select it either. base itself is not modified.
func ForceHTTP1(base *http.Transport) *http.Transport {
	var t *http.Transport
	switch {
	case base != nil:
		t = base.Clone()
	default:
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			t = dt.Clone()
		} else {
			t = &http.Transport{Proxy: http.ProxyFromEnvironment}
		}
	}
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if t.TLSClientConfig != nil && len(t.TLSClientConfig.NextProtos) > 0 {
		kept := t.TLSClientConfig.NextProtos[:0:0]
		for _, p := range t.TLSClientConfig.NextProtos {
			if p != "h2" {
				kept = append(kept, p)
			}
		}
		t.TLSClientConfig.NextProtos = kept
	}
	return t
}

// RoundTrip implements [http.RoundTripper]. It clones req, sets the credential
// header on the clone when the host filter admits it, and forwards the clone
// to Base. The header is deleted from the clone (which the response's Request
// field points at) once Base returns, whether or not it succeeded.
//
// A request whose host is excluded by [Transport.Hosts] is forwarded to Base
// unchanged and the Token is not touched. A request for an admitted host
// over a scheme other than https fails with [ErrInsecureScheme] unless
// [Transport.AllowInsecureHTTP] or an "http://" Hosts entry opted in; it is
// not sent.
//
// Errors: [ErrNilRequest]; [ErrInsecureScheme]; [ErrNoToken] for a nil
// Token; an error wrapping [secmem.ErrDestroyed] or [secmem.ErrSealed] for a
// Token in that state; [ErrBasicUsername]; otherwise whatever Base returns.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return nil, errors.New("httpauth: RoundTrip on a nil *Transport")
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	switch t.decide(req) {
	case forward:
		return t.base().RoundTrip(req)
	case refuse:
		return nil, ErrInsecureScheme
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

// decision is what RoundTrip does with a request.
type decision int

const (
	inject  decision = iota // admitted host, acceptable scheme
	forward                 // host not listed: pass through untouched
	refuse                  // admitted host, cleartext scheme, no opt-in
)

// decide applies the Hosts filter and the scheme rule. With an empty filter
// every host is admitted and only the scheme is checked. Otherwise every
// entry whose host matches gets to admit the request's scheme; if none does
// but at least one matched the host, the request is refused rather than
// forwarded bare, so a downgrade fails loudly.
func (t *Transport) decide(req *http.Request) decision {
	var scheme, host string
	if req.URL != nil {
		scheme = strings.ToLower(req.URL.Scheme)
		host = req.URL.Host
	}
	secure := scheme == "https"
	if len(t.Hosts) == 0 {
		if secure || t.AllowInsecureHTTP {
			return inject
		}
		return refuse
	}
	if req.URL == nil {
		return forward
	}
	matched := false
	for _, entry := range t.Hosts {
		entryScheme, entryHost := splitHostEntry(entry)
		if !strings.EqualFold(host, entryHost) {
			continue
		}
		matched = true
		switch {
		case entryScheme == "":
			if secure || t.AllowInsecureHTTP {
				return inject
			}
		case entryScheme == scheme:
			return inject
		}
	}
	if matched {
		return refuse
	}
	return forward
}

// splitHostEntry separates an optional "scheme://" prefix from a Hosts
// entry. The scheme is returned lower-cased; a trailing "/" on the host is
// dropped so "https://api.example.com/" reads as intended.
func splitHostEntry(entry string) (scheme, host string) {
	if i := strings.Index(entry, "://"); i >= 0 {
		scheme = strings.ToLower(entry[:i])
		entry = entry[i+3:]
	}
	return scheme, strings.TrimSuffix(entry, "/")
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
