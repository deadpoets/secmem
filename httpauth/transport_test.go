package httpauth_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/httpauth"
)

// newToken copies raw into a SecureBuffer. raw is left intact for the test to
// compare against (NewBuffer wipes its input). An allocation failure is an
// environment condition — an mlock refusal — not a test failure, so it skips.
func newToken(t *testing.T, raw []byte) *secmem.SecureBuffer {
	t.Helper()
	in := bytes.Clone(raw)
	tok, err := secmem.NewBuffer(in)
	if err != nil {
		t.Skipf("secmem.NewBuffer: %v (an mlock refusal is an environment condition)", err)
	}
	t.Cleanup(func() { _ = tok.Destroy() })
	return tok
}

// capture records what a test server saw: the header of every request, in
// arrival order, plus the Basic credentials of the last one.
type capture struct {
	mu      sync.Mutex
	headers []http.Header
	user    string
	pass    string
	basicOK bool
}

func (c *capture) handle(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers = append(c.headers, r.Header.Clone())
	c.user, c.pass, c.basicOK = r.BasicAuth()
	w.WriteHeader(http.StatusNoContent)
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.headers)
}

func (c *capture) last() http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.headers) == 0 {
		return nil
	}
	return c.headers[len(c.headers)-1]
}

// newServer starts an httptest server whose every request lands in the
// returned capture. hostOf returns the value req.URL.Host will carry.
func newServer(t *testing.T) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(c.handle))
	t.Cleanup(srv.Close)
	return srv, c
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", srv.URL, err)
	}
	return u.Host
}

// do performs one GET through tr and closes the body. Tests that need the
// response itself call RoundTrip directly.
func do(t *testing.T, tr http.RoundTripper, target string) error {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestBearer_HeaderArrivesVerbatim(t *testing.T) {
	t.Parallel()
	// A byte >= 0x80 is obs-text, which net/http accepts in a field value;
	// a control byte (NUL, CR, LF) is refused by net/http itself before any
	// bytes hit the wire, so it is not something this package needs to handle.
	raw := []byte("tok-3n_with-a-\xff-byte")
	tok := newToken(t, raw)
	srv, c := newServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	got := c.last().Get("Authorization")
	want := "Bearer " + string(raw)
	if got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestNewHeader_CustomHeaderEmptyPrefix(t *testing.T) {
	t.Parallel()
	raw := []byte("api-key-0123456789")
	tok := newToken(t, raw)
	srv, c := newServer(t)

	tr := httpauth.NewHeader("X-API-Key", "", tok, srv.Client().Transport)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	h := c.last()
	if got := h.Get("X-API-Key"); got != string(raw) {
		t.Fatalf("X-API-Key = %q, want %q", got, raw)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Fatalf("Authorization should be unset, got %q", got)
	}
}

func TestNewHeader_EmptyHeaderDefaultsToAuthorization(t *testing.T) {
	t.Parallel()
	raw := []byte("tok")
	tok := newToken(t, raw)
	srv, c := newServer(t)

	tr := httpauth.NewHeader("", "Token ", tok, srv.Client().Transport)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Token tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Token tok")
	}
}

func TestBasic_ServerDecodesUserAndPassword(t *testing.T) {
	t.Parallel()
	// A colon inside the password and non-ASCII bytes, including one that is
	// not valid UTF-8: BasicAuth splits at the FIRST colon and hands the rest
	// back as raw bytes in a string, so both must survive intact.
	raw := []byte("p:a:ss wörd\xff")
	tok := newToken(t, raw)
	srv, c := newServer(t)

	tr := httpauth.NewBasic("alice", tok, srv.Client().Transport)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	c.mu.Lock()
	user, pass, ok := c.user, c.pass, c.basicOK
	c.mu.Unlock()
	if !ok {
		t.Fatalf("server's BasicAuth() rejected the header %q", c.last().Get("Authorization"))
	}
	if user != "alice" {
		t.Errorf("username = %q, want %q", user, "alice")
	}
	if !bytes.Equal([]byte(pass), raw) {
		t.Errorf("password = %q, want %q", pass, raw)
	}
	if !strings.HasPrefix(c.last().Get("Authorization"), "Basic ") {
		t.Errorf("Authorization = %q, want a Basic scheme", c.last().Get("Authorization"))
	}
}

func TestBasic_UsernameWithColonIsRefused(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("pw"))
	srv, c := newServer(t)

	tr := httpauth.NewBasic("a:b", tok, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, httpauth.ErrBasicUsername) {
		t.Fatalf("err = %v, want ErrBasicUsername", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server, want 0", n)
	}
}

func TestLiteralWithBasicPrefix_IsPlainHeaderNotBase64(t *testing.T) {
	t.Parallel()
	raw := []byte("already-encoded")
	tok := newToken(t, raw)
	srv, c := newServer(t)

	tr := &httpauth.Transport{Base: srv.Client().Transport, Prefix: "Basic ", Token: tok}
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Basic already-encoded" {
		t.Fatalf("Authorization = %q, want the prefix set verbatim with no encoding", got)
	}
}

func TestRoundTrip_CallerRequestUntouchedAndResponseRequestScrubbed(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Keep", "1")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("server saw Authorization = %q, want %q", got, "Bearer tok")
	}
	if _, present := req.Header["Authorization"]; present {
		t.Errorf("caller's request was mutated: Authorization = %q", req.Header.Get("Authorization"))
	}
	if resp.Request == nil {
		t.Fatal("response has no Request")
	}
	if resp.Request == req {
		t.Error("response.Request is the caller's request; RoundTrip must send a clone")
	}
	if _, present := resp.Request.Header["Authorization"]; present {
		t.Errorf("response.Request still carries Authorization = %q", resp.Request.Header.Get("Authorization"))
	}
	if got := resp.Request.Header.Get("X-Keep"); got != "1" {
		t.Errorf("unrelated header lost from the clone: X-Keep = %q", got)
	}
}

// errBase captures the request it is handed, records whether the header was
// present at that moment, and fails the round trip.
type errBase struct {
	header  string
	seen    string
	present bool
	req     *http.Request
}

var errBaseFailed = errors.New("base failed")

func (b *errBase) RoundTrip(req *http.Request) (*http.Response, error) {
	b.req = req
	b.seen = req.Header.Get(b.header)
	_, b.present = req.Header[http.CanonicalHeaderKey(b.header)]
	return nil, errBaseFailed
}

func TestRoundTrip_HeaderDeletedFromCloneEvenWhenBaseFails(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	base := &errBase{header: "Authorization"}

	tr := httpauth.NewBearer(tok, base)
	err := do(t, tr, "http://example.invalid/")
	if !errors.Is(err, errBaseFailed) {
		t.Fatalf("err = %v, want the base's error", err)
	}
	if !base.present || base.seen != "Bearer tok" {
		t.Fatalf("base saw Authorization = %q (present=%v), want %q", base.seen, base.present, "Bearer tok")
	}
	if _, present := base.req.Header["Authorization"]; present {
		t.Errorf("clone still carries Authorization after a failed round trip")
	}
}

func TestDestroyedToken_ErrDestroyedAndNoRequest(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)
	if err := tok.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Fatalf("err = %v, want errors.Is(err, secmem.ErrDestroyed)", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server, want 0", n)
	}
}

func TestDestroyedToken_BasicAlsoReportsErrDestroyed(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("pw"))
	srv, c := newServer(t)
	if err := tok.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	tr := httpauth.NewBasic("alice", tok, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Fatalf("err = %v, want errors.Is(err, secmem.ErrDestroyed)", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server, want 0", n)
	}
}

func TestSealedToken_ErrSealedThenWorksAfterUnseal(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)
	if err := tok.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, secmem.ErrSealed) {
		t.Fatalf("err = %v, want errors.Is(err, secmem.ErrSealed)", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server while sealed, want 0", n)
	}

	if err := tok.Unseal(); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip after Unseal: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization after Unseal = %q, want %q", got, "Bearer tok")
	}
}

func TestNilToken_ErrNoToken(t *testing.T) {
	t.Parallel()
	srv, c := newServer(t)
	tr := httpauth.NewBearer(nil, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, httpauth.ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server, want 0", n)
	}
}

func TestHosts_OnlyListedHostGetsHeader(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv1, c1 := newServer(t)
	srv2, c2 := newServer(t)

	tr := httpauth.NewBearer(tok, srv1.Client().Transport, hostOf(t, srv1))
	if err := do(t, tr, srv1.URL); err != nil {
		t.Fatalf("RoundTrip to listed host: %v", err)
	}
	if err := do(t, tr, srv2.URL); err != nil {
		t.Fatalf("RoundTrip to unlisted host: %v", err)
	}
	if got := c1.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("listed host saw Authorization = %q, want %q", got, "Bearer tok")
	}
	if c2.count() != 1 {
		t.Fatalf("unlisted host received %d request(s), want 1 (forwarded unchanged)", c2.count())
	}
	if got := c2.last().Get("Authorization"); got != "" {
		t.Errorf("unlisted host saw Authorization = %q, want none", got)
	}
}

func TestHosts_ExcludedRequestDoesNotTouchToken(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)
	if err := tok.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// A destroyed token would fail the request if it were read at all.
	tr := httpauth.NewBearer(tok, srv.Client().Transport, "other.example.invalid")
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip to an excluded host read the token: %v", err)
	}
	if c.count() != 1 {
		t.Fatalf("server received %d request(s), want 1", c.count())
	}
}

func TestHosts_MatchIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	// httptest binds a numeric address, so upper-case the hostname the
	// request will use instead and keep the filter as written.
	host := hostOf(t, srv)
	tr := httpauth.NewBearer(tok, srv.Client().Transport, "LOCALHOST:"+portOf(t, host))
	target := "http://localhost:" + portOf(t, host)
	if err := do(t, tr, target); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q (case-insensitive host match)", got, "Bearer tok")
	}
}

func portOf(t *testing.T, host string) string {
	t.Helper()
	i := strings.LastIndex(host, ":")
	if i < 0 {
		t.Fatalf("host %q has no port", host)
	}
	return host[i+1:]
}

func TestHosts_PortIsPartOfTheMatch(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	// The bare hostname without the port does not match "host:port".
	host := hostOf(t, srv)
	tr := httpauth.NewBearer(tok, srv.Client().Transport, strings.TrimSuffix(host, ":"+portOf(t, host)))
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want none: the filter entry lacks the port", got)
	}
}

// redirectServer 302s every request to target.
func redirectServer(t *testing.T, target string) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.headers = append(c.headers, r.Header.Clone())
		c.mu.Unlock()
		http.Redirect(w, r, target, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestRedirect_HostsKeepsHeaderOffTheSecondHost(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv2, c2 := newServer(t)
	srv1, c1 := redirectServer(t, srv2.URL+"/target")

	tr := httpauth.NewBearer(tok, srv1.Client().Transport, hostOf(t, srv1))
	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv1.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: the redirect was not followed", resp.StatusCode, http.StatusNoContent)
	}
	if got := c1.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("first host saw Authorization = %q, want %q", got, "Bearer tok")
	}
	if got := c2.last().Get("Authorization"); got != "" {
		t.Errorf("second host saw Authorization = %q, want none", got)
	}
}

// With Hosts empty the credential follows a redirect to another host. This
// is the documented footgun, asserted so that the documentation stays true:
// http.Client drops Authorization from the request it was given, but this
// transport sits below the Client and injects on every hop it is handed.
func TestRedirect_EmptyHostsLeaksHeaderToSecondHost_DocumentedFootgun(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv2, c2 := newServer(t)
	srv1, c1 := redirectServer(t, srv2.URL+"/target")

	tr := httpauth.NewBearer(tok, srv1.Client().Transport)
	client := &http.Client{Transport: tr}
	resp, err := client.Get(srv1.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()
	if got := c1.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("first host saw Authorization = %q, want %q", got, "Bearer tok")
	}
	if got := c2.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("second host saw Authorization = %q; the documented behaviour is that it receives %q", got, "Bearer tok")
	}
}

func TestBaseNil_UsesDefaultTransport(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	tr := httpauth.NewBearer(tok, nil)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip via http.DefaultTransport: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestNilRequest_Error(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	tr := httpauth.NewBearer(tok, nil)
	resp, err := tr.RoundTrip(nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, httpauth.ErrNilRequest) {
		t.Fatalf("err = %v, want ErrNilRequest", err)
	}
}

func TestNilTransport_Error(t *testing.T) {
	t.Parallel()
	var tr *httpauth.Transport
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("nil *Transport RoundTrip returned no error")
	}
}

func TestRoundTrip_ConcurrentUse(t *testing.T) {
	t.Parallel()
	raw := []byte("concurrent-token")
	tok := newToken(t, raw)
	srv, c := newServer(t)
	tr := httpauth.NewBearer(tok, srv.Client().Transport)

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := do(t, tr, srv.URL); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("RoundTrip: %v", err)
	}
	if c.count() != n {
		t.Fatalf("server received %d request(s), want %d", c.count(), n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, h := range c.headers {
		if got := h.Get("Authorization"); got != "Bearer "+string(raw) {
			t.Errorf("request %d: Authorization = %q", i, got)
		}
	}
}
