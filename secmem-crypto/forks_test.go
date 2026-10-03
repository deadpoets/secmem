package secmemcrypto

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/deadpoets/secmem/secmem-crypto/internal/forks"
)

// forks.json is the record of every piece of third-party code copied into
// this module, and these tests are what stop it becoming a file nobody
// maintains. They need no network and no module cache: the questions here
// are about this tree and its own prose. Whether UPSTREAM has moved is
// internal/forkcheck's question, asked by the Fork Watch workflow.
//
// Shown to fail, each by the mutation it exists to catch: a fork directory
// renamed without touching the manifest, a doc.go whose version claim was
// edited to a different release, an unregistered copy with a LICENSE of its
// own, a NOTICE section with no entry, and the wordlist's recorded hash
// changed.

func loadForks(t *testing.T) *forks.Manifest {
	t.Helper()
	m, err := forks.Load(forks.Name)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestForks_PathsExist: every entry names something that is here. A fork
// moved or renamed without the manifest following is the way this file would
// start lying first.
func TestForks_PathsExist(t *testing.T) {
	t.Parallel()
	for _, f := range loadForks(t).Forks {
		if _, err := os.Stat(f.Path); err != nil {
			t.Errorf("%s: path %s: %v", f.ID, f.Path, err)
		}
		for _, id := range f.Identity {
			if _, err := os.Stat(id.Ours); err != nil {
				t.Errorf("%s: identity claim on %s: %v", f.ID, id.Ours, err)
			}
		}
		for _, c := range f.Claims {
			if _, err := os.Stat(c); err != nil {
				t.Errorf("%s: claims file %s: %v", f.ID, c, err)
			}
		}
	}
}

// TestForks_ClaimsStateTheForkPoint: each claims file says which upstream
// version the copy came from. The version in the documentation was true when
// written and had nothing keeping it true; this is that something.
func TestForks_ClaimsStateTheForkPoint(t *testing.T) {
	t.Parallel()
	for _, f := range loadForks(t).Forks {
		if f.ForkPoint == "" {
			continue // an embedded file has a hash, not a version
		}
		for _, c := range f.Claims {
			b, err := os.ReadFile(c)
			if err != nil {
				t.Errorf("%s: %v", f.ID, err)
				continue
			}
			if !strings.Contains(string(b), f.ForkPoint) {
				t.Errorf("%s: %s does not state the fork point %s; the manifest and the prose disagree", f.ID, c, f.ForkPoint)
			}
		}
	}
}

// TestForks_NoOtherUpstreamVersionInForkDir catches a half-finished port: a
// file inside a fork re-pointed at a newer release while its siblings, the
// NOTICE and the manifest still say the old one. Only the fork point and the
// release it is recorded as unchanged through may appear.
func TestForks_NoOtherUpstreamVersionInForkDir(t *testing.T) {
	t.Parallel()
	version := regexp.MustCompile(`v0\.\d+\.\d+`)
	for _, f := range loadForks(t).Forks {
		if f.Upstream.Kind != forks.KindGomod {
			continue
		}
		err := filepath.WalkDir(f.Path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if ext := filepath.Ext(p); ext != ".go" && ext != ".s" {
				return nil
			}
			b, readErr := os.ReadFile(p)
			if readErr != nil {
				return readErr
			}
			for _, v := range version.FindAllString(string(b), -1) {
				if v != f.ForkPoint && v != f.UnchangedThrough {
					t.Errorf("%s: %s mentions %s, which is neither the fork point %s nor the release it is unchanged through %s", f.ID, p, v, f.ForkPoint, f.UnchangedThrough)
				}
			}
			return nil
		})
		if err != nil {
			t.Errorf("%s: %v", f.ID, err)
		}
	}
}

// TestForks_EveryCopiedDirectoryIsRegistered: a directory carrying its own
// LICENSE is copied code by this module's convention, so it must have an
// entry. Without this, a future fork could arrive with no provenance record
// and nothing watching its upstream.
func TestForks_EveryCopiedDirectoryIsRegistered(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	for _, f := range loadForks(t).Forks {
		registered[filepath.Clean(f.Path)] = true
	}
	entries, err := os.ReadDir("internal")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join("internal", e.Name())
		if _, err := os.Stat(filepath.Join(dir, "LICENSE")); err != nil {
			continue // not copied code
		}
		if !registered[filepath.Clean(dir)] {
			t.Errorf("%s has its own LICENSE, so it is copied code, but %s has no entry for it", dir, forks.Name)
		}
	}
}

// TestForks_NoticeSectionsMatchTheManifest: NOTICE is the licence-level
// record and the manifest is the maintenance-level one. They list the same
// things or one of them is wrong.
func TestForks_NoticeSectionsMatchTheManifest(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	// A section heading is a line followed by a line of dashes.
	lines := strings.Split(string(b), "\n")
	sections := map[string]bool{}
	for i := 0; i+1 < len(lines); i++ {
		head, under := strings.TrimSpace(lines[i]), strings.TrimSpace(lines[i+1])
		if head == "" || under == "" || strings.Trim(under, "-") != "" {
			continue
		}
		sections[strings.TrimSuffix(head, "/")] = true
	}
	if len(sections) == 0 {
		t.Fatal("no NOTICE sections found: the heading convention changed, so this test is no longer checking anything")
	}
	for _, f := range loadForks(t).Forks {
		p := strings.TrimSuffix(filepath.ToSlash(f.Path), "/")
		if !sections[p] {
			t.Errorf("%s: NOTICE has no section for %s", f.ID, p)
		}
		delete(sections, p)
	}
	for s := range sections {
		t.Errorf("NOTICE has a section for %s with no entry in %s", s, forks.Name)
	}
}

// TestForks_EmbeddedFileHashes: the embedded file still hashes to what
// NOTICE's claim of byte identity with the published original rests on. The
// scheduled job additionally re-fetches the original; this half needs no
// network, so it runs in ordinary CI.
func TestForks_EmbeddedFileHashes(t *testing.T) {
	t.Parallel()
	for _, f := range loadForks(t).Forks {
		if f.Upstream.Kind != forks.KindURL {
			continue
		}
		if f.SHA256 == "" {
			t.Errorf("%s: an embedded file needs a recorded sha256", f.ID)
			continue
		}
		got, err := forks.SHA256File(f.Path)
		if err != nil {
			t.Errorf("%s: %v", f.ID, err)
			continue
		}
		if got != f.SHA256 {
			t.Errorf("%s: %s hashes to %s, manifest records %s", f.ID, f.Path, got, f.SHA256)
		}
	}
}

// TestForks_EntriesAreUsable: the fields internal/forkcheck needs are
// present and the modes are ones it implements, so a scheduled run cannot
// report "unknown" because of a typo in the manifest.
func TestForks_EntriesAreUsable(t *testing.T) {
	t.Parallel()
	for _, f := range loadForks(t).Forks {
		if f.ID == "" || f.Path == "" || f.Notes == "" {
			t.Errorf("%+v: id, path and notes are all required", f)
		}
		switch f.Upstream.Kind {
		case forks.KindGomod:
			if f.Upstream.Module == "" || len(f.Upstream.Paths) == 0 {
				t.Errorf("%s: a gomod upstream needs a module and at least one path", f.ID)
			}
			if f.ForkPoint == "" || f.UnchangedThrough == "" {
				t.Errorf("%s: a gomod upstream needs fork_point and unchanged_through", f.ID)
			}
			if len(f.Identity) == 0 {
				t.Errorf("%s: no identity claims, so nothing would notice upstream changing the verbatim parts", f.ID)
			}
		case forks.KindGoroot:
			if len(f.Upstream.Paths) == 0 || len(f.Identity) == 0 {
				t.Errorf("%s: a goroot upstream needs paths and identity claims", f.ID)
			}
		case forks.KindURL:
			if f.Upstream.URL == "" {
				t.Errorf("%s: a url upstream needs the url", f.ID)
			}
		default:
			t.Errorf("%s: unknown upstream kind %q", f.ID, f.Upstream.Kind)
		}
		for _, id := range f.Identity {
			switch id.Mode {
			case forks.ModeBytes:
			case forks.ModeCode:
			case forks.ModeFunc, forks.ModeBlock:
				if id.Name == "" {
					t.Errorf("%s: mode %s needs a name", f.ID, id.Mode)
				}
			default:
				t.Errorf("%s: unknown identity mode %q", f.ID, id.Mode)
			}
			if id.Ours == "" || id.Theirs == "" {
				t.Errorf("%s: an identity claim needs both sides", f.ID)
			}
		}
	}
}
