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
// Usage:
//
//	t, err := httpauth.NewBearer(token, httpauth.WithHosts("api.example.com"))
//	if err != nil {
//		return err
//	}
//	client := &http.Client{Transport: t}
//
// A host decision is required. Every constructor fails with [ErrNoHosts]
// unless it is given [WithHosts], naming the hosts the credential is meant
// for, or [WithAnyHost], which injects into every request. The reason is the
// redirect footgun: a Transport sits BELOW [net/http.Client]. The Client's
// rule of dropping Authorization on a cross-domain redirect applies to
// headers on the request it was handed, not to what a RoundTripper injects on
// each hop — the Client builds the redirected request without the header,
// hands it back down, and an unfiltered transport injects again, sending the
// credential to whatever host the redirect named. Making the filter an
// explicit choice means forgetting it is an error rather than a leak.
//
// The downgrade footgun: a host filter is scheme-blind unless told
// otherwise, and a redirect from https://api.example.com to
// http://api.example.com passes it. The credential is therefore never
// injected into a request whose scheme is not https unless the caller opts
// in — with [WithInsecureHTTP] for every host not pinned to https by an
// "https://host" entry, or with an "http://host" entry for one — and a
// cleartext request to an admitted host fails with [ErrInsecureScheme]
// rather than going out without the header, so the downgrade is visible
// instead of a puzzling 401.
//
// A Transport is immutable once constructed: its configuration is unexported
// and fixed by the constructor, which validates it and fails closed on
// anything incoherent. It is safe for concurrent use. The token's own state
// can still change — the caller may seal, truncate or destroy it — and
// RoundTrip reports that per request.
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
// [secmem.SecureWipe] before the window closes. The value is set on a clone
// of the request and nowhere else: the caller's request never carries it,
// and the response's Request field is pointed back at the caller's request,
// so keeping a response does not keep the credential. The clone is referenced
// only by the base transport, which may still be reading it after RoundTrip
// returns and so must not be modified; the value becomes unreachable when
// the base transport lets go of that request.
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
//     configures a base transport that never negotiates h2, for callers who
//     want the shorter lifetime more than they want multiplexing.
//   - The header-writer's pooled sorter. HTTP/1 header writing sorts the
//     Header map's key/value slices through a sync.Pool-backed sorter; the
//     []string holding the credential stays reachable from that pool entry
//     until a later header write that draws the same sorter overwrites that
//     slot (which takes at least as many keys as the credential's sorted
//     position) or replaces the slice with a larger one, or the pool drops
//     the sorter.
//   - An [net/http/httptrace.ClientTrace] with WroteHeaderField set is handed
//     the value as a string, and keeps whatever it keeps.
//   - Anything a base transport that logs or caches requests keeps for
//     itself.
//
// The package is stdlib + secmem only.
package httpauth

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/deadpoets/secmem"
)

// ErrNoToken is returned by [NewBearer], [NewHeader] and [NewBasic] for a nil
// token or password, and by [Transport.RoundTrip] on a Transport that was not
// built by one of them (the zero value), which has no token to inject.
var ErrNoToken = errors.New("httpauth: no token")

// ErrNilRequest is returned by [Transport.RoundTrip] for a nil request.
var ErrNilRequest = errors.New("httpauth: nil request")

// ErrBasicUsername is returned by [NewBasic] when the username contains ':'.
// RFC 7617 forbids it: the server splits user-pass at the first colon, so
// such a name cannot be transmitted correctly and is refused rather than sent
// wrong.
var ErrBasicUsername = errors.New("httpauth: basic username must not contain ':'")

// ErrInsecureScheme is returned by [Transport.RoundTrip] when the request is
// for a host the credential is meant for but its URL scheme is not https and
// nothing opted in to cleartext. The request is not sent.
var ErrInsecureScheme = errors.New("httpauth: refusing to send the credential over cleartext http (use WithInsecureHTTP, or list the host as \"http://host\" to opt in)")

// ErrNoHosts is returned by [NewBearer], [NewHeader] and [NewBasic] when
// neither [WithHosts] (with at least one entry) nor [WithAnyHost] was given.
// The host decision is required because the credential otherwise follows a
// redirect to any host; see the package documentation.
var ErrNoHosts = errors.New("httpauth: no host filter: pass WithHosts, or WithAnyHost to inject into every request")

// ErrInvalidConfig is returned, wrapped with the detail, by [NewBearer],
// [NewHeader] and [NewBasic] for a configuration that cannot be used as
// given: a header name that is not a valid HTTP field name, a prefix
// containing CR, LF or NUL, a malformed host entry, or both [WithHosts] and
// [WithAnyHost].
var ErrInvalidConfig = errors.New("httpauth: invalid configuration")

// defaultHeader is the header set when NewHeader is given an empty name.
const defaultHeader = "Authorization"

// Transport is an [http.RoundTripper] that sets a credential header on each
// request from a [secmem.SecureBuffer]. Construct one with [NewBearer],
// [NewHeader] or [NewBasic]; the zero value refuses every request with
// [ErrNoToken].
//
// A Transport is immutable after construction and safe for concurrent use.
// It does not own the token: the caller keeps it alive for as long as the
// Transport is in use and destroys it afterwards.
//
// The caller's request is never modified: RoundTrip clones it, sets the
// header on the clone, and returns a response whose Request field is the
// caller's request, not the clone.
type Transport struct {
	base     http.RoundTripper // nil means http.DefaultTransport, read per request
	header   string            // field name, validated, never empty
	prefix   string            // precedes the token; unused when basic
	token    *secmem.SecureBuffer
	hosts    []hostEntry // parsed WithHosts entries; empty iff anyHost
	anyHost  bool
	insecure bool

	// basic is set by NewBasic: the value is "Basic " +
	// base64(basicUser + ":" + token) rather than prefix + token.
	basic     bool
	basicUser string
}

// hostEntry is one parsed WithHosts entry. scheme is "", "http" or "https".
type hostEntry struct {
	scheme string
	host   string
}

// config collects the options before a constructor validates them.
type config struct {
	hosts    []string
	anyHost  bool
	insecure bool
	base     http.RoundTripper
}

// Option configures a [Transport] at construction. A nil Option is ignored.
type Option func(*config)

// WithHosts restricts injection to requests whose URL host is listed. The
// host is compared with req.URL.Host case-insensitively, port included as
// written: "api.example.com" does not match "api.example.com:8443".
//
// An entry may carry a scheme. "https://api.example.com" admits only https
// requests to that host; "http://localhost:8080" admits only cleartext ones,
// and is the per-host opt-in for them. A bare "api.example.com" admits https,
// and http only with [WithInsecureHTTP]. A single trailing "/" is tolerated.
// A request to a listed host whose scheme no entry admits fails with
// [ErrInsecureScheme]; a request to an unlisted host is forwarded to the base
// transport untouched, and the token is not read.
//
// An entry that is empty, carries a scheme other than http or https, or
// contains a path, query, fragment, userinfo or whitespace makes the
// constructor fail with [ErrInvalidConfig]. WithHosts may be given more than
// once; the entries accumulate. WithHosts with no entries adds nothing, and
// on its own leaves the constructor failing with [ErrNoHosts]. The entries
// are copied: changing the caller's slice afterwards has no effect.
func WithHosts(entries ...string) Option {
	entries = slices.Clone(entries)
	return func(c *config) { c.hosts = append(c.hosts, entries...) }
}

// WithAnyHost injects the credential into every request, whatever its host.
//
// Use it only when the client never follows redirects or the API never
// issues one. A Transport sits below [net/http.Client], so the Client's rule
// of dropping Authorization on a cross-domain redirect does not apply to
// what is injected here: on a redirect to another host, that host receives
// the credential. The scheme rule still applies — cleartext requests are
// refused unless [WithInsecureHTTP] is also given. It cannot be combined
// with [WithHosts].
func WithAnyHost() Option {
	return func(c *config) { c.anyHost = true }
}

// WithInsecureHTTP permits injecting the credential into a request whose URL
// scheme is not https, for every host admitted through a bare (scheme-less)
// [WithHosts] entry or by [WithAnyHost]. It does not override an entry that
// carries a scheme: a host listed only as "https://host" still refuses
// cleartext with [ErrInsecureScheme]. Without it, a plain http URL, or an
// https→http redirect on an admitted host, fails with ErrInsecureScheme
// instead of sending the token in cleartext. Prefer an "http://host" entry,
// which opts in one host rather than all of them.
func WithInsecureHTTP() Option {
	return func(c *config) { c.insecure = true }
}

// WithBase sets the RoundTripper that performs the requests. nil, the
// default, means [net/http.DefaultTransport], looked up per request.
func WithBase(rt http.RoundTripper) Option {
	return func(c *config) { c.base = rt }
}

// NewBearer returns a Transport that sets "Authorization: Bearer <token>".
// It fails with [ErrNoToken] for a nil token, [ErrNoHosts] without a host
// decision, and an error wrapping [ErrInvalidConfig] for an invalid option.
func NewBearer(token *secmem.SecureBuffer, opts ...Option) (*Transport, error) {
	return NewHeader(defaultHeader, "Bearer ", token, opts...)
}

// NewHeader returns a Transport that sets header to prefix followed by the
// token, e.g. NewHeader("X-API-Key", "", key, WithHosts("api.example.com"))
// for an API-key header. An empty header means "Authorization". The prefix is
// set verbatim, with no encoding: a prefix of "Basic " expects a token that
// is already base64; only [NewBasic] encodes.
//
// It fails with [ErrNoToken] for a nil token, [ErrNoHosts] without a host
// decision, and an error wrapping [ErrInvalidConfig] for a header name that
// is not an RFC 7230 token, a prefix containing CR, LF or NUL, or an invalid
// option.
func NewHeader(header, prefix string, token *secmem.SecureBuffer, opts ...Option) (*Transport, error) {
	if header == "" {
		header = defaultHeader
	}
	if !validFieldName(header) {
		return nil, fmt.Errorf("%w: header name %q is not a valid HTTP field name", ErrInvalidConfig, header)
	}
	if strings.ContainsAny(prefix, "\r\n\x00") {
		return nil, fmt.Errorf("%w: header prefix %q contains CR, LF or NUL", ErrInvalidConfig, prefix)
	}
	return build(&Transport{header: header, prefix: prefix}, token, opts)
}

// NewBasic returns a Transport that sets
// "Authorization: Basic base64(username:password)" (RFC 7617). It fails with
// [ErrBasicUsername] when username contains ':', [ErrNoToken] for a nil
// password, [ErrNoHosts] without a host decision, and an error wrapping
// [ErrInvalidConfig] for an invalid option.
//
// The username is held as a plain string: it is the identifier, not the
// secret. The password never becomes a string on its own; per request it is
// copied into one wiped scratch slice alongside the username, encoded into a
// second, and only the finished header value is a string.
func NewBasic(username string, password *secmem.SecureBuffer, opts ...Option) (*Transport, error) {
	if strings.Contains(username, ":") {
		return nil, ErrBasicUsername
	}
	return build(&Transport{header: defaultHeader, basic: true, basicUser: username}, password, opts)
}

// build applies opts to t, validates the host decision and entries, and
// returns t, or nil and the first error.
func build(t *Transport, token *secmem.SecureBuffer, opts []Option) (*Transport, error) {
	if token == nil {
		return nil, ErrNoToken
	}
	var c config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	switch {
	case len(c.hosts) > 0 && c.anyHost:
		return nil, fmt.Errorf("%w: WithHosts and WithAnyHost are contradictory", ErrInvalidConfig)
	case len(c.hosts) == 0 && !c.anyHost:
		return nil, ErrNoHosts
	}
	hosts := make([]hostEntry, 0, len(c.hosts))
	for _, raw := range c.hosts {
		e, err := parseHostEntry(raw)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, e)
	}
	t.token = token
	t.base = c.base
	t.hosts = hosts
	t.anyHost = c.anyHost
	t.insecure = c.insecure
	return t, nil
}

// parseHostEntry separates an optional "scheme://" prefix from a WithHosts
// entry and validates what is left. The scheme is lower-cased and must be
// http or https; one trailing "/" is dropped so "https://api.example.com/"
// reads as intended. What remains must be a non-empty host[:port] with no
// path, query, fragment, userinfo or whitespace.
func parseHostEntry(entry string) (hostEntry, error) {
	var e hostEntry
	rest := entry
	if i := strings.Index(rest, "://"); i >= 0 {
		e.scheme = strings.ToLower(rest[:i])
		if e.scheme != "http" && e.scheme != "https" {
			return hostEntry{}, fmt.Errorf("%w: host entry %q: scheme must be http or https", ErrInvalidConfig, entry)
		}
		rest = rest[i+3:]
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return hostEntry{}, fmt.Errorf("%w: host entry %q: empty host", ErrInvalidConfig, entry)
	}
	if strings.ContainsAny(rest, "/?#@") || strings.ContainsFunc(rest, unicode.IsSpace) {
		return hostEntry{}, fmt.Errorf("%w: host entry %q: want host or host:port, optionally with an http:// or https:// scheme", ErrInvalidConfig, entry)
	}
	e.host = rest
	return e, nil
}

// validFieldName reports whether name is an RFC 7230 token: one or more
// tchar ("!#$%&'*+-.^_`|~", digits, letters).
func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// ForceHTTP1 returns a copy of base — of http.DefaultTransport when base is
// nil — that negotiates HTTP/1.1 only, for use with [WithBase] by callers
// who want the credential kept out of HTTP/2's per-connection HPACK dynamic
// table (see the package doc). It clears ForceAttemptHTTP2, sets an empty
// TLSNextProto map (net/http's documented way to disable its bundled http2),
// sets Protocols to HTTP/1 alone (that field overrides the other two when the
// base set it), and drops "h2" from the TLS config's advertised protocols so
// the server cannot select it either. base itself is not modified.
//
// With a nil base, if http.DefaultTransport has been replaced by something
// other than an *http.Transport, there is nothing to copy: the result is a
// bare &http.Transport{Proxy: http.ProxyFromEnvironment} with the settings
// above, and none of the default transport's timeouts, dialer or connection
// limits.
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
	// Protocols, when set, is consulted ahead of both fields above, and Clone
	// copied the base's: a base that enabled h2 through it would still speak
	// h2. A fresh value, so the base's is not written through.
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
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
// to the base transport. The clone is not touched again once the base has it
// — a RoundTripper may still be reading the request after it returns, until
// the response body is closed — so instead of deleting the header from it,
// RoundTrip sets the response's Request field to req, which never carried
// the credential.
//
// A request whose host [WithHosts] does not list is forwarded to the base
// transport unchanged and the token is not touched. A request for an
// admitted host over a scheme other than https fails with
// [ErrInsecureScheme] unless [WithInsecureHTTP] or an "http://" host entry
// opted in; it is not sent. The request body is closed on every path,
// including the ones that fail before the base transport is called.
//
// Errors: a non-sentinel error for a nil *Transport; [ErrNilRequest];
// [ErrNoToken] for the zero Transport; [ErrInsecureScheme]; an error
// wrapping [secmem.ErrDestroyed] (or [secmem.ErrWiped], which wraps it) or
// [secmem.ErrSealed] for a token in that state; a "token is empty" error for
// a live token of length zero (after Truncate(0)); a "token changed length
// during read" error when the token is truncated concurrently with the read;
// otherwise whatever the base transport returns. In every case but the last
// the request is not sent.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		closeBody(req)
		return nil, errors.New("httpauth: RoundTrip on a nil *Transport")
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	// Only the zero value has no token; the constructors refuse nil. Checked
	// before the filter, because an empty filter on the zero value would
	// otherwise forward every request unauthenticated.
	if t.token == nil {
		closeBody(req)
		return nil, ErrNoToken
	}
	switch t.decide(req) {
	case forward:
		return t.baseRT().RoundTrip(req)
	case refuse:
		closeBody(req)
		return nil, ErrInsecureScheme
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
	// the base RoundTrip does not run inside it, because network I/O in a
	// Scrub window pins the thread and holds the preemption signal blocked for
	// the duration of the round trip.
	var value string
	var err error
	if t.basic {
		value, err = t.basicValue()
	} else {
		value, err = t.headerValue()
	}
	if err != nil {
		closeBody(req)
		return nil, err
	}
	clone.Header.Set(t.header, value)

	resp, rerr := t.baseRT().RoundTrip(clone)

	// Nothing can wipe a Go string; the most that can be done is to leave no
	// reference behind, so the collector — and runtime/secret on a build
	// where it is active — can reclaim it. The response's Request field
	// points at the clone, which would keep the credential reachable for as
	// long as the caller keeps the response, so it is pointed at the caller's
	// request instead. The clone itself is left as it is: net/http may still
	// be writing it on another goroutine (an early response, a cancelled
	// HTTP/2 stream), and deleting from its Header would race that read.
	if resp != nil {
		resp.Request = req
	}
	return resp, rerr
}

// closeBody closes req's body on a path where the request is never handed to
// the base transport. A RoundTripper must close the body on every path,
// errors included: http.Client does not, and a pipe or file body would stay
// open.
func closeBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

// decision is what RoundTrip does with a request.
type decision int

const (
	inject  decision = iota // admitted host, acceptable scheme
	forward                 // host not listed: pass through untouched
	refuse                  // admitted host, cleartext scheme, no opt-in
)

// decide applies the host filter and the scheme rule. With WithAnyHost every
// host is admitted and only the scheme is checked. Otherwise every entry
// whose host matches gets to admit the request's scheme; if none does but at
// least one matched the host, the request is refused rather than forwarded
// bare, so a downgrade fails loudly.
func (t *Transport) decide(req *http.Request) decision {
	var scheme, host string
	if req.URL != nil {
		scheme = strings.ToLower(req.URL.Scheme)
		host = req.URL.Host
	}
	secure := scheme == "https"
	if t.anyHost {
		if secure || t.insecure {
			return inject
		}
		return refuse
	}
	if req.URL == nil {
		return forward
	}
	matched := false
	for _, e := range t.hosts {
		if !strings.EqualFold(host, e.host) {
			continue
		}
		matched = true
		switch e.scheme {
		case "":
			if secure || t.insecure {
				return inject
			}
		case scheme:
			return inject
		}
	}
	if matched {
		return refuse
	}
	return forward
}

// baseRT returns the RoundTripper that performs requests.
func (t *Transport) baseRT() http.RoundTripper {
	if t.base == nil {
		return http.DefaultTransport
	}
	return t.base
}

// headerValue builds prefix + token inside a scrub window.
func (t *Transport) headerValue() (string, error) {
	var value string
	err := secmem.ScrubErr(func() error {
		n := t.token.Len()
		buf := make([]byte, len(t.prefix)+n)
		// Deferred so the scratch is wiped on the error paths too.
		defer secmem.SecureWipe(buf)
		copy(buf, t.prefix)
		if err := t.copyToken(buf[len(t.prefix):], n); err != nil {
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
// string; both scratches are wiped. NewBasic has already refused a username
// containing ':'.
func (t *Transport) basicValue() (string, error) {
	const prefix = "Basic "
	var value string
	err := secmem.ScrubErr(func() error {
		n := t.token.Len()
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

// copyToken copies the whole token into dst, which is exactly n = token.Len()
// bytes as measured before the copy. CopyOut reports the buffer's own state:
// secmem.ErrDestroyed or secmem.ErrSealed, wrapped here so errors.Is finds
// them. A short copy means the buffer was truncated between the length read
// and the copy, and is refused rather than sent as a shorter credential.
func (t *Transport) copyToken(dst []byte, n int) error {
	if n == 0 {
		// Len is 0 for a destroyed buffer, and also for a live one that was
		// truncated to nothing (the constructors refuse empty input, but
		// Truncate(0) does not). Ask CopyOut so a destroyed, wiped or sealed
		// buffer reports its state; any other answer — for a live empty
		// buffer it is an offset-out-of-range error — means the token is
		// simply empty, and that is what the caller is told.
		_, err := t.token.CopyOut(dst, 0)
		if errors.Is(err, secmem.ErrDestroyed) || errors.Is(err, secmem.ErrSealed) {
			return fmt.Errorf("httpauth: reading token: %w", err)
		}
		return errors.New("httpauth: token is empty")
	}
	got, err := t.token.CopyOut(dst, 0)
	if err != nil {
		return fmt.Errorf("httpauth: reading token: %w", err)
	}
	if got != n {
		return fmt.Errorf("httpauth: token changed length during read (%d of %d bytes)", got, n)
	}
	return nil
}
