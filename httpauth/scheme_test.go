package httpauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deadpoets/secmem/httpauth"
)

// newPlainServer starts a cleartext httptest server, for the tests that
// exercise the http opt-in paths and the one that must use
// http.DefaultTransport (which cannot verify the httptest certificate).
func newPlainServer(t *testing.T) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(c.handle))
	t.Cleanup(srv.Close)
	return srv, c
}

// ── Scheme rule ─────────────────────────────────────────────────────────────

func TestInsecure_BareHostEntryRefusesHTTP(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, hostOf(t, srv))
	err := do(t, tr, srv.URL)
	if !errors.Is(err, httpauth.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server over cleartext, want 0", n)
	}
}

func TestInsecure_EmptyHostsRefusesHTTP(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	err := do(t, tr, srv.URL)
	if !errors.Is(err, httpauth.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server over cleartext, want 0", n)
	}
}

func TestInsecure_RefusedRequestDoesNotTouchToken(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, _ := newPlainServer(t)
	if err := tok.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// A destroyed token would report ErrDestroyed if it were read; the scheme
	// rule must come first.
	tr := httpauth.NewBearer(tok, srv.Client().Transport)
	if err := do(t, tr, srv.URL); !errors.Is(err, httpauth.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
}

func TestInsecure_AllowInsecureHTTPOptsIn(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, hostOf(t, srv))
	tr.AllowInsecureHTTP = true
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestInsecure_HTTPEntryOptsInPerHost(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, "http://"+hostOf(t, srv))
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestInsecure_HTTPSEntryRefusesHTTP(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, "https://"+hostOf(t, srv)+"/")
	if err := do(t, tr, srv.URL); !errors.Is(err, httpauth.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
	if n := c.count(); n != 0 {
		t.Fatalf("%d request(s) reached the server, want 0", n)
	}
}

func TestInsecure_HTTPSEntryAdmitsHTTPS(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, "HTTPS://"+hostOf(t, srv))
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestInsecure_UnlistedHostForwardedRegardlessOfScheme(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newPlainServer(t)

	tr := httpauth.NewBearer(tok, srv.Client().Transport, "other.example.invalid")
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip to an unlisted host: %v", err)
	}
	if c.count() != 1 {
		t.Fatalf("server received %d request(s), want 1", c.count())
	}
	if got := c.last().Get("Authorization"); got != "" {
		t.Fatalf("unlisted host saw Authorization = %q, want none", got)
	}
}

// TestRedirect_HTTPSToHTTPIsRefused is the downgrade the scheme-blind filter
// let through: the first host answers over TLS and redirects to a cleartext
// URL on a host the filter also admits. The credential must not follow.
func TestRedirect_HTTPSToHTTPIsRefused(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	plain, c2 := newPlainServer(t)
	tlsSrv, c1 := redirectServer(t, plain.URL+"/target")

	tr := httpauth.NewBearer(tok, tlsSrv.Client().Transport, hostOf(t, tlsSrv), hostOf(t, plain))
	client := &http.Client{Transport: tr}
	resp, err := client.Get(tlsSrv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, httpauth.ErrInsecureScheme) {
		t.Fatalf("client.Get err = %v, want ErrInsecureScheme", err)
	}
	if got := c1.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("TLS host saw Authorization = %q, want %q", got, "Bearer tok")
	}
	if n := c2.count(); n != 0 {
		t.Errorf("cleartext host received %d request(s), want 0", n)
	}
}

// ── HTTP/1.1 recipe ─────────────────────────────────────────────────────────

// protoServer starts a TLS server with h2 enabled that records the protocol
// of each request.
func protoServer(t *testing.T) (*httptest.Server, *capture, *[]string) {
	t.Helper()
	c := &capture{}
	var protos []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		protos = append(protos, r.Proto)
		c.mu.Unlock()
		c.handle(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, c, &protos
}

func TestForceHTTP1_RequestIsHTTP11(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c, protos := protoServer(t)
	base, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httptest client transport is %T", srv.Client().Transport)
	}

	// Control: the server does speak h2 to a willing client.
	if err := do(t, httpauth.NewBearer(tok, base), srv.URL); err != nil {
		t.Fatalf("RoundTrip (h2): %v", err)
	}
	// Recipe: the same base, forced to HTTP/1.1.
	if err := do(t, httpauth.NewBearer(tok, httpauth.ForceHTTP1(base)), srv.URL); err != nil {
		t.Fatalf("RoundTrip (forced h1): %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(*protos) != 2 {
		t.Fatalf("server saw %d request(s), want 2", len(*protos))
	}
	if (*protos)[0] != "HTTP/2.0" {
		t.Errorf("control request was %s, want HTTP/2.0 (the server did not enable h2, so the test proves nothing)", (*protos)[0])
	}
	if (*protos)[1] != "HTTP/1.1" {
		t.Errorf("ForceHTTP1 request was %s, want HTTP/1.1", (*protos)[1])
	}
	for i, h := range c.headers {
		if got := h.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("request %d: Authorization = %q", i, got)
		}
	}
	// net/http fills in base.TLSNextProto itself on first use, so only the
	// field ForceHTTP1 is responsible for can prove the argument was cloned.
	if !base.ForceAttemptHTTP2 {
		t.Errorf("ForceHTTP1 modified its argument")
	}
}

func TestForceHTTP1_NilBaseClonesDefault(t *testing.T) {
	t.Parallel()
	tr := httpauth.ForceHTTP1(nil)
	if tr == nil || http.RoundTripper(tr) == http.DefaultTransport {
		t.Fatalf("ForceHTTP1(nil) = %v, want a fresh clone of DefaultTransport", tr)
	}
	if tr.ForceAttemptHTTP2 || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Errorf("ForceHTTP1(nil) did not disable h2: ForceAttemptHTTP2=%v TLSNextProto=%v", tr.ForceAttemptHTTP2, tr.TLSNextProto)
	}
}
