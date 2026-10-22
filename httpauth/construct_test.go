package httpauth_test

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/deadpoets/secmem"
	"github.com/deadpoets/secmem/httpauth"
)

// constructors builds a Transport of each kind from the same token and
// options, so every construction rule is checked against all three.
func constructors(tok *secmem.SecureBuffer) map[string]func(...httpauth.Option) (*httpauth.Transport, error) {
	return map[string]func(...httpauth.Option) (*httpauth.Transport, error){
		"NewBearer": func(o ...httpauth.Option) (*httpauth.Transport, error) { return httpauth.NewBearer(tok, o...) },
		"NewHeader": func(o ...httpauth.Option) (*httpauth.Transport, error) {
			return httpauth.NewHeader("X-API-Key", "", tok, o...)
		},
		"NewBasic": func(o ...httpauth.Option) (*httpauth.Transport, error) { return httpauth.NewBasic("alice", tok, o...) },
	}
}

// wantErr asserts a constructor failed closed: the error matches want and no
// Transport came back with it.
func wantErr(t *testing.T, name string, tr *httpauth.Transport, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", name, err, want)
	}
	if tr != nil {
		t.Errorf("%s: a Transport was returned alongside the error", name)
	}
}

// Forgetting the host decision must be an error, not an every-host
// transport: that is the redirect leak the requirement exists to prevent.
func TestNew_NoHostDecisionIsErrNoHosts(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	for name, mk := range constructors(tok) {
		tr, err := mk()
		wantErr(t, name+"()", tr, err, httpauth.ErrNoHosts)
		tr, err = mk(httpauth.WithHosts())
		wantErr(t, name+"(WithHosts())", tr, err, httpauth.ErrNoHosts)
		tr, err = mk(httpauth.WithHosts(), httpauth.WithInsecureHTTP(), httpauth.WithBase(http.DefaultTransport))
		wantErr(t, name+"(WithHosts(), other options)", tr, err, httpauth.ErrNoHosts)
	}
}

func TestNew_HostsAndAnyHostConflict(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	for name, mk := range constructors(tok) {
		tr, err := mk(httpauth.WithHosts("api.example.com"), httpauth.WithAnyHost())
		wantErr(t, name, tr, err, httpauth.ErrInvalidConfig)
		tr, err = mk(httpauth.WithAnyHost(), httpauth.WithHosts("api.example.com"))
		wantErr(t, name+" (reversed)", tr, err, httpauth.ErrInvalidConfig)
	}
}

func TestNew_NilTokenIsErrNoToken(t *testing.T) {
	t.Parallel()
	for name, mk := range constructors(nil) {
		tr, err := mk(httpauth.WithAnyHost())
		wantErr(t, name, tr, err, httpauth.ErrNoToken)
	}
}

func TestNewHeader_InvalidHeaderNameRefused(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	for _, h := range []string{
		"X API Key",         // space
		"X-Key:",            // separator
		"X-Key: evil",       // a whole header line smuggled in the name
		"X-Key\r\nX-Evil",   // CRLF
		"X-K\x00ey",         // NUL
		"X-Ключ",            // non-ASCII
		"(Authorization)",   // separators
		"Authorization\t",   // tab
		"X-Key\x7f",         // DEL
		"\"Authorization\"", // quotes
	} {
		tr, err := httpauth.NewHeader(h, "", tok, httpauth.WithAnyHost())
		wantErr(t, "header "+strings.ReplaceAll(h, "\x00", `\x00`), tr, err, httpauth.ErrInvalidConfig)
	}
	for _, h := range []string{"X-API-Key", "x_api.key", "!#$%&'*+-.^_`|~09AZaz"} {
		if _, err := httpauth.NewHeader(h, "", tok, httpauth.WithAnyHost()); err != nil {
			t.Errorf("valid header name %q refused: %v", h, err)
		}
	}
}

func TestNewHeader_PrefixInjectionRefused(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	for _, p := range []string{
		"Bearer \r\nX-Evil: 1\r\nX-Pad: ",
		"Bearer\n",
		"Bearer\r",
		"Bearer\x00",
	} {
		tr, err := httpauth.NewHeader("", p, tok, httpauth.WithAnyHost())
		wantErr(t, "prefix "+strings.NewReplacer("\r", `\r`, "\n", `\n`, "\x00", `\x00`).Replace(p), tr, err, httpauth.ErrInvalidConfig)
	}
	if _, err := httpauth.NewHeader("", "Token token=", tok, httpauth.WithAnyHost()); err != nil {
		t.Errorf("ordinary prefix refused: %v", err)
	}
}

func TestWithHosts_InvalidEntriesRefused(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	for _, e := range []string{
		"",
		"/",
		"https://",
		"https:///",
		"ftp://api.example.com",
		"://api.example.com",
		"api.example.com/v1",
		"https://api.example.com/v1",
		"https://api.example.com//",
		"api.example.com?x=1",
		"api.example.com#frag",
		"user@api.example.com",
		"https://user:pw@api.example.com",
		"api.example.com ",
		" api.example.com",
		"api .example.com",
		"api.example.com\t",
		"api.example.com\n",
	} {
		for name, mk := range constructors(tok) {
			tr, err := mk(httpauth.WithHosts("ok.example.com", e))
			wantErr(t, name+" entry "+strings.NewReplacer("\t", `\t`, "\n", `\n`).Replace(e), tr, err, httpauth.ErrInvalidConfig)
		}
	}
	for _, e := range []string{
		"api.example.com",
		"api.example.com:8443",
		"https://api.example.com/",
		"HTTPS://api.example.com",
		"Http://localhost:8080/",
		"[::1]:8080",
	} {
		if _, err := httpauth.NewBearer(tok, httpauth.WithHosts(e)); err != nil {
			t.Errorf("valid entry %q refused: %v", e, err)
		}
	}
}

// The filter is fixed at construction: neither changing the slice passed to
// WithHosts before the constructor runs, nor changing it afterwards, admits
// a host that was not listed.
func TestWithHosts_CallerSliceDoesNotAliasTheFilter(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)

	// After construction.
	hosts := []string{"listed.example.invalid"}
	tr := mustNew(t)(httpauth.NewBearer(tok, httpauth.WithBase(srv.Client().Transport), httpauth.WithHosts(hosts...)))
	hosts[0] = hostOf(t, srv)
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "" {
		t.Errorf("after construction: Authorization = %q, want none: the caller's slice reached the filter", got)
	}

	// Between WithHosts and the constructor.
	hosts = []string{"listed.example.invalid"}
	opt := httpauth.WithHosts(hosts...)
	hosts[0] = hostOf(t, srv)
	tr = mustNew(t)(httpauth.NewBearer(tok, httpauth.WithBase(srv.Client().Transport), opt))
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "" {
		t.Errorf("before construction: Authorization = %q, want none: the caller's slice reached the option", got)
	}
}

func TestWithHosts_GivenTwiceAccumulates(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv1, c1 := newServer(t)
	srv2, c2 := newServer(t)
	tr := mustNew(t)(httpauth.NewBearer(tok,
		httpauth.WithBase(srv1.Client().Transport),
		httpauth.WithHosts(hostOf(t, srv1)),
		httpauth.WithHosts(hostOf(t, srv2))))
	for _, u := range []string{srv1.URL, srv2.URL} {
		if err := do(t, tr, u); err != nil {
			t.Fatalf("RoundTrip %s: %v", u, err)
		}
	}
	if got := c1.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("first WithHosts host: Authorization = %q, want %q", got, "Bearer tok")
	}
	if got := c2.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("second WithHosts host: Authorization = %q, want %q", got, "Bearer tok")
	}
}

func TestNilOptionIgnored(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("tok"))
	srv, c := newServer(t)
	tr := mustNew(t)(httpauth.NewBearer(tok, nil, httpauth.WithBase(srv.Client().Transport), nil, httpauth.WithAnyHost(), nil))
	if err := do(t, tr, srv.URL); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := c.last().Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer tok")
	}
	// A nil Option is not a host decision.
	if _, err := httpauth.NewBearer(tok, nil); !errors.Is(err, httpauth.ErrNoHosts) {
		t.Errorf("NewBearer(tok, nil): err = %v, want ErrNoHosts", err)
	}
}

// One Transport shared by goroutines that hit a listed and an unlisted host,
// with Bearer and Basic, so -race sees the filter, the token read and the
// clone on every path at once.
func TestRoundTrip_ConcurrentMixedHosts(t *testing.T) {
	t.Parallel()
	tok := newToken(t, []byte("pw"))
	listed, cl := newServer(t)
	unlisted, cu := newServer(t)
	bearer := mustNew(t)(httpauth.NewBearer(tok, httpauth.WithBase(listed.Client().Transport), httpauth.WithHosts(hostOf(t, listed))))
	basic := mustNew(t)(httpauth.NewBasic("alice", tok, httpauth.WithBase(listed.Client().Transport), httpauth.WithHosts("https://"+hostOf(t, listed))))

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, 4*n)
	for range n {
		for _, tr := range []*httpauth.Transport{bearer, basic} {
			for _, u := range []string{listed.URL, unlisted.URL} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := do(t, tr, u); err != nil {
						errs <- err
					}
				}()
			}
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("RoundTrip: %v", err)
	}
	cl.mu.Lock()
	for i, h := range cl.headers {
		if got := h.Get("Authorization"); got != "Bearer pw" && !strings.HasPrefix(got, "Basic ") {
			t.Errorf("listed request %d: Authorization = %q", i, got)
		}
	}
	cl.mu.Unlock()
	cu.mu.Lock()
	for i, h := range cu.headers {
		if got := h.Get("Authorization"); got != "" {
			t.Errorf("unlisted request %d: Authorization = %q, want none", i, got)
		}
	}
	cu.mu.Unlock()
	if cl.count() != 2*n || cu.count() != 2*n {
		t.Errorf("listed/unlisted received %d/%d, want %d each", cl.count(), cu.count(), 2*n)
	}
}
