package forks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.58.0", "v0.56.0", 1},
		{"v0.56.0", "v0.58.0", -1},
		{"v0.58.0", "v0.58.0", 0},
		{"v0.100.0", "v0.99.9", 1}, // numeric, not lexical
		{"v1.0.0", "v0.999.0", 1},
	} {
		got, err := CompareVersions(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"0.58.0", "v0.58", "v0.58.0-rc.1", "go1.27", "v01.2.3", ""} {
		if _, err := CompareVersions(bad, "v0.1.0"); err == nil {
			t.Errorf("CompareVersions(%q, ...) accepted a non-release version", bad)
		}
	}
}

func TestCheckReviewed(t *testing.T) {
	t.Parallel()
	fork := func(unchanged string, rv ...Review) *Fork {
		return &Fork{ID: "x", Upstream: Upstream{Kind: KindGomod}, ForkPoint: "v0.56.0", UnchangedThrough: unchanged, Reviewed: rv}
	}
	ok := Review{Through: "v0.58.0", Reason: "loong64 only"}

	if err := CheckReviewed(fork("v0.57.0")); err != nil {
		t.Errorf("no reviews: %v", err)
	}
	if err := CheckReviewed(fork("v0.58.0", ok)); err != nil {
		t.Errorf("one review at unchanged_through: %v", err)
	}
	if err := CheckReviewed(fork("v0.60.0", ok, Review{Through: "v0.59.0", Reason: "r"})); err != nil {
		t.Errorf("two ascending reviews: %v", err)
	}

	for name, f := range map[string]*Fork{
		"no reason":                     fork("v0.58.0", Review{Through: "v0.58.0", Reason: "  "}),
		"at the fork point":             fork("v0.58.0", Review{Through: "v0.56.0", Reason: "r"}),
		"below the fork point":          fork("v0.58.0", Review{Through: "v0.55.0", Reason: "r"}),
		"not ascending":                 fork("v0.60.0", ok, Review{Through: "v0.58.0", Reason: "r"}),
		"past unchanged_through":        fork("v0.57.0", ok),
		"not a release":                 fork("v0.58.0", Review{Through: "v0.58.0-rc.1", Reason: "r"}),
		"on an upstream it cannot diff": {ID: "x", Upstream: Upstream{Kind: KindGoroot}, ForkPoint: "go1.26", UnchangedThrough: "go1.27", Reviewed: []Review{ok}},
		"unchanged_through not version": fork("", ok),
	} {
		if err := CheckReviewed(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	f := fork("v0.58.0", ok, Review{Through: "v0.59.0", Reason: "r"})
	if got := f.Base(); got != "v0.59.0" {
		t.Errorf("Base with reviews = %s, want the newest review", got)
	}
	if got := fork("v0.57.0").Base(); got != "v0.56.0" {
		t.Errorf("Base without reviews = %s, want the fork point", got)
	}
}

// manifestText is laid out the way forks.json is committed: inline arrays and
// one-line objects, which a re-marshal would expand.
const manifestText = `{
  "_comment": ["a"],
  "forks": [
    {
      "id": "one",
      "path": "p1",
      "notes": "n",
      "upstream": { "kind": "gomod", "module": "m", "paths": ["a", "b"] },
      "fork_point": "v0.1.0",
      "unchanged_through": "v0.1.0",
      "claims": ["c"],
      "identity": [{ "mode": "bytes", "ours": "o", "theirs": "t" }]
    },
    {
      "id": "two",
      "path": "p2",
      "notes": "n",
      "upstream": { "kind": "gomod", "module": "m", "paths": ["a"] },
      "fork_point": "v0.1.0",
      "unchanged_through": "v0.1.0",
      "claims": ["c"]
    }
  ]
}
`

// TestSetUnchangedThrough: the update is a one-line diff per fork, touches
// only the named entry, and leaves the hand layout alone. The previous
// implementation re-marshalled the manifest and rewrote all of it.
func TestSetUnchangedThrough(t *testing.T) {
	t.Parallel()
	name := filepath.Join(t.TempDir(), Name)
	if err := os.WriteFile(name, []byte(manifestText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetUnchangedThrough(name, map[string]string{"two": "v0.2.0"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	before, after := strings.Split(manifestText, "\n"), strings.Split(string(got), "\n")
	if len(before) != len(after) {
		t.Fatalf("line count changed from %d to %d: the file was reformatted", len(before), len(after))
	}
	var changed []string
	for i := range before {
		if before[i] != after[i] {
			changed = append(changed, after[i])
		}
	}
	if len(changed) != 1 || strings.TrimSpace(changed[0]) != `"unchanged_through": "v0.2.0",` {
		t.Fatalf("changed lines = %q, want only two's unchanged_through", changed)
	}
	m, err := Load(name)
	if err != nil {
		t.Fatal(err)
	}
	if m.Forks[0].UnchangedThrough != "v0.1.0" || m.Forks[1].UnchangedThrough != "v0.2.0" {
		t.Errorf("parsed back as %s / %s", m.Forks[0].UnchangedThrough, m.Forks[1].UnchangedThrough)
	}
}

// TestSetUnchangedThrough_RefusesAmbiguousEntry: an entry with the field
// twice cannot be edited safely as text, so nothing is written.
func TestSetUnchangedThrough_RefusesAmbiguousEntry(t *testing.T) {
	t.Parallel()
	name := filepath.Join(t.TempDir(), Name)
	text := strings.Replace(manifestText, `"claims": ["c"]
    }
  ]`, `"claims": ["c"],
      "x": { "unchanged_through": "v9.9.9" }
    }
  ]`, 1)
	if text == manifestText {
		t.Fatal("test fixture did not apply")
	}
	if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetUnchangedThrough(name, map[string]string{"two": "v0.2.0"}); err == nil {
		t.Fatal("edited an entry with two unchanged_through fields")
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != text {
		t.Error("the file was written despite the refusal")
	}
}
