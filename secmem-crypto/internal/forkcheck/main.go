// Command forkcheck reports whether the upstream of any copied code in
// forks.json has moved since this module forked it.
//
// It diffs upstream against ITSELF — the copied paths at fork_point against
// the same paths at upstream's newest release — rather than against our copy.
// A fork-versus-upstream diff is permanently large, because the modifications
// are the whole reason the fork exists, so it reports nothing a reader can
// act on. Upstream against itself is empty in the steady state, which is what
// makes this safe to run unattended: output means something happened.
//
// Three questions per fork, each answerable without judgement:
//
//   - Did upstream change the copied paths since fork_point? If not, the
//     manifest's unchanged_through can be advanced (-update does it). If so,
//     the diff is the port decision, and a human makes it.
//   - Are the pieces documented as verbatim still identical to upstream's
//     NEWEST release? Each fork's upstream_identity_test.go asks this of the
//     version the module resolves, which only moves when something bumps the
//     dependency; asking it of the newest release sees a changed function
//     before the bump arrives, and even if none ever does.
//   - Is there an advisory against the forked code at fork_point? This is the
//     blind spot a copy creates: govulncheck reads a module's dependency
//     graph, and a fork is not in one, so an advisory affecting x/crypto's
//     argon2 or blowfish would never be reported against this module. The
//     query asks the OSV database for the upstream module at fork_point and
//     keeps only advisories whose affected import paths are the copied ones.
//
// Exit status is 0 whether or not upstream moved: an upstream release is an
// event outside this repository, and a job that fails for it would block
// unrelated work. The caller decides what to do with the report — the Fork
// Watch workflow opens a tracking issue. -strict inverts that for a caller
// that wants a non-zero status (nothing in CI uses it today).
//
// Network and toolchain failures are reported as "unknown" rather than as
// drift, so an offline run is honest instead of either green or alarming.
//
// Usage, from the module root:
//
//	go run ./internal/forkcheck            # human-readable report
//	go run ./internal/forkcheck -json      # machine-readable, for CI
//	go run ./internal/forkcheck -update    # advance unchanged_through where clean
//	go run ./internal/forkcheck -offline   # skip anything needing the network
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/deadpoets/secmem/secmem-crypto/internal/forks"
)

// result is one fork's verdict. Status is the headline: "clean" (upstream has
// not moved and every verbatim claim holds), "drift" (it has, or a claim no
// longer holds), or "unknown" (the check could not be made).
type result struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Upstream string   `json:"upstream"`
	Newest   string   `json:"newest,omitempty"`
	Findings []string `json:"findings,omitempty"`
	Diff     string   `json:"diff,omitempty"`
	Advisory []string `json:"advisories,omitempty"`
	Stale    string   `json:"manifest_can_record,omitempty"`
}

func main() {
	var (
		jsonOut = flag.Bool("json", false, "write the report as JSON on stdout instead of text")
		out     = flag.String("out", "", "also write the JSON report to this file")
		counts  = flag.String("counts", "", "append drift= and unknown= counts to this file, for a CI step's outputs")
		update  = flag.Bool("update", false, "advance unchanged_through in the manifest where upstream has not moved")
		offline = flag.Bool("offline", false, "skip every check that needs the network")
		strict  = flag.Bool("strict", false, "exit non-zero when any fork has drifted")
	)
	flag.Parse()

	m, err := forks.Load(forks.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forkcheck: %v\n", err)
		os.Exit(2)
	}

	results := make([]result, 0, len(m.Forks))
	for i := range m.Forks {
		f := &m.Forks[i]
		r := check(f, *offline)
		if *update && r.Stale != "" {
			f.UnchangedThrough = r.Stale
			r.Findings = append(r.Findings, "manifest updated: unchanged_through = "+r.Stale)
			r.Stale = ""
		}
		results = append(results, r)
	}

	if *update {
		if err := forks.Save(forks.Name, m); err != nil {
			fmt.Fprintf(os.Stderr, "forkcheck: %v\n", err)
			os.Exit(2)
		}
	}

	if *jsonOut {
		if err := writeJSON(os.Stdout, results); err != nil {
			die(err)
		}
	} else {
		fmt.Print(report(results))
	}

	// -out and -counts let one run serve a human reading the log, a machine
	// reading the report and a CI step reading the tallies. Two runs would be
	// two queries of upstream, and could disagree with each other.
	if *out != "" {
		if err := writeJSONFile(*out, results); err != nil {
			die(err)
		}
	}
	if *counts != "" {
		if err := writeCounts(*counts, results); err != nil {
			die(err)
		}
	}

	if *strict {
		for _, r := range results {
			if r.Status == "drift" {
				os.Exit(1)
			}
		}
	}
}

func check(f *forks.Fork, offline bool) result {
	switch f.Upstream.Kind {
	case forks.KindGomod:
		return checkGomod(f, offline)
	case forks.KindGoroot:
		return checkGoroot(f)
	case forks.KindURL:
		return checkURL(f, offline)
	default:
		return result{ID: f.ID, Status: "unknown", Findings: []string{"unknown upstream kind " + f.Upstream.Kind}}
	}
}

// checkGomod is the main path: a module proxy has every version, so both
// sides of the comparison are fetchable.
func checkGomod(f *forks.Fork, offline bool) result {
	r := result{ID: f.ID, Status: "clean", Upstream: f.Upstream.Module}
	if offline {
		r.Status = "unknown"
		r.Findings = []string{"offline: upstream releases not queried"}
		return r
	}

	newest, err := newestVersion(f.Upstream.Module)
	if err != nil {
		r.Status = "unknown"
		r.Findings = []string{err.Error()}
		return r
	}
	r.Newest = newest

	oldDir, err := moduleDir(f.Upstream.Module, f.ForkPoint)
	if err != nil {
		r.Status = "unknown"
		r.Findings = []string{err.Error()}
		return r
	}
	newDir := oldDir
	if newest != f.ForkPoint {
		if newDir, err = moduleDir(f.Upstream.Module, newest); err != nil {
			r.Status = "unknown"
			r.Findings = []string{err.Error()}
			return r
		}
	}

	// Question 1: did upstream change the copied paths?
	var diffs []string
	for _, p := range f.Upstream.Paths {
		d, err := diffTrees(filepath.Join(oldDir, filepath.FromSlash(p)), filepath.Join(newDir, filepath.FromSlash(p)))
		if err != nil {
			r.Status = "unknown"
			r.Findings = append(r.Findings, err.Error())
			return r
		}
		if d != "" {
			diffs = append(diffs, "=== "+p+" ("+f.ForkPoint+" -> "+newest+")\n"+d)
		}
	}
	if len(diffs) > 0 {
		r.Status = "drift"
		r.Findings = append(r.Findings, fmt.Sprintf("upstream changed the copied paths between %s and %s", f.ForkPoint, newest))
		r.Diff = strings.Join(diffs, "\n")
	} else if f.UnchangedThrough != newest {
		r.Stale = newest
	}

	// Question 2: do the verbatim claims still hold against the newest
	// release? Checked even when the tree diff is empty, because a claim can
	// also break from our side — an edit here that the identity test would
	// catch only on the version the module happens to resolve.
	for _, id := range f.Identity {
		if err := compare(id, "", newDir); err != nil {
			r.Status = "drift"
			r.Findings = append(r.Findings, err.Error())
		}
	}

	// Question 3: is anything published against the code as forked?
	adv, err := advisories(f.Upstream.Module, f.ForkPoint, f.Upstream.Paths)
	switch {
	case err != nil:
		r.Findings = append(r.Findings, "advisory query: "+err.Error())
	case len(adv) > 0:
		r.Status = "drift"
		r.Advisory = adv
		r.Findings = append(r.Findings, fmt.Sprintf("%d advisory(ies) affect the forked paths at %s", len(adv), f.ForkPoint))
	}
	return r
}

// checkGoroot compares against the toolchain running this command. The
// fork's own upstream_identity_test.go does the same, so the value here is
// the canary: run it under a release candidate and a stdlib change is seen
// before the toolchain pin moves.
func checkGoroot(f *forks.Fork) result {
	r := result{ID: f.ID, Status: "clean", Upstream: "go toolchain"}
	root, err := goEnv("GOROOT")
	if err != nil {
		r.Status = "unknown"
		r.Findings = []string{err.Error()}
		return r
	}
	ver, err := goEnv("GOVERSION")
	if err == nil {
		r.Newest = ver
	}
	for _, id := range f.Identity {
		if err := compare(id, "", root); err != nil {
			r.Status = "drift"
			r.Findings = append(r.Findings, err.Error())
		}
	}
	// A stdlib copy carries no version to advance automatically: which Go
	// release the claim covers is a sentence in doc.go and NOTICE as well as
	// a manifest field, so the suggestion is made and left to a human.
	if r.Status == "clean" && r.Newest != "" && !strings.HasPrefix(r.Newest, f.UnchangedThrough) {
		r.Findings = append(r.Findings, "identical under "+r.Newest+", which unchanged_through ("+f.UnchangedThrough+") does not cover: update the manifest and the prose together")
	}
	return r
}

// checkURL re-fetches an embedded file and compares both the published bytes
// and the committed ones against the recorded hash, so either side moving is
// visible. forks_test.go checks the committed side without the network.
func checkURL(f *forks.Fork, offline bool) result {
	r := result{ID: f.ID, Status: "clean", Upstream: f.Upstream.URL}
	local, err := forks.SHA256File(f.Path)
	if err != nil {
		r.Status = "unknown"
		r.Findings = []string{err.Error()}
		return r
	}
	if local != f.SHA256 {
		r.Status = "drift"
		r.Findings = append(r.Findings, "the committed file no longer hashes to the recorded sha256")
		return r
	}
	if offline {
		r.Findings = append(r.Findings, "offline: the published copy was not fetched")
		return r
	}
	remote, err := sha256URL(f.Upstream.URL)
	if err != nil {
		r.Status = "unknown"
		r.Findings = []string{"fetch " + f.Upstream.URL + ": " + err.Error()}
		return r
	}
	if remote != local {
		r.Status = "drift"
		r.Findings = append(r.Findings, "the published file has changed since it was embedded; NOTICE claims byte identity with it")
	}
	return r
}

// newestVersion asks the proxy for every release and takes the last, which
// `go list -m -versions` prints in semver order.
func newestVersion(module string) (string, error) {
	//nolint:gosec // G204: a fixed argv with no shell; module comes from this
	// repository's own forks.json, which forks_test.go validates.
	out, err := exec.Command("go", "list", "-m", "-versions", module).Output()
	if err != nil {
		return "", fmt.Errorf("go list -m -versions %s: %w", module, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", fmt.Errorf("go list -m -versions %s: no versions", module)
	}
	return fields[len(fields)-1], nil
}

// moduleDir downloads one version and returns its directory in the module
// cache. The cache is read-only, which is why nothing here writes to it.
func moduleDir(module, version string) (string, error) {
	ref := module + "@" + version
	//nolint:gosec // G204: as above — a fixed argv, and ref is a module path
	// and version from forks.json.
	out, err := exec.Command("go", "mod", "download", "-json", ref).Output()
	if err != nil {
		return "", fmt.Errorf("go mod download %s: %w", ref, err)
	}
	var meta struct {
		Dir   string
		Error string
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		return "", fmt.Errorf("go mod download %s: %w", ref, err)
	}
	if meta.Error != "" {
		return "", fmt.Errorf("go mod download %s: %s", ref, meta.Error)
	}
	if meta.Dir == "" {
		return "", fmt.Errorf("go mod download %s: no directory", ref)
	}
	return meta.Dir, nil
}

// diffTrees reports what changed between two directories as a unified diff,
// without shelling out to diff(1) — this runs on Windows too. Added and
// removed files are named rather than printed: a file upstream added is a
// port decision on its own, and its contents belong in the review, not in a
// scheduled job's summary.
func diffTrees(oldDir, newDir string) (string, error) {
	oldFiles, err := walkFiles(oldDir)
	if err != nil {
		return "", err
	}
	newFiles, err := walkFiles(newDir)
	if err != nil {
		return "", err
	}
	var out []string
	for rel, oldSum := range oldFiles {
		newSum, ok := newFiles[rel]
		switch {
		case !ok:
			out = append(out, "- removed upstream: "+rel)
		case newSum != oldSum:
			d, err := fileDiff(filepath.Join(oldDir, rel), filepath.Join(newDir, rel))
			if err != nil {
				return "", err
			}
			out = append(out, "~ changed upstream: "+rel+"\n"+d)
		}
	}
	for rel := range newFiles {
		if _, ok := oldFiles[rel]; !ok {
			out = append(out, "+ added upstream: "+rel)
		}
	}
	slices.Sort(out)
	return strings.Join(out, "\n"), nil
}

func walkFiles(dir string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		sum, err := forks.SHA256File(p)
		if err != nil {
			return err
		}
		files[rel] = sum
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	return files, nil
}

// fileDiff is a line-level report: which lines left and which arrived. It is
// not a minimal edit script — an upstream change to a forked algorithm gets
// read line by line by whoever ports it, and "these lines differ" is the
// input to that, not a substitute for it.
func fileDiff(oldPath, newPath string) (string, error) {
	a, err := forks.ReadFile(oldPath)
	if err != nil {
		return "", err
	}
	b, err := forks.ReadFile(newPath)
	if err != nil {
		return "", err
	}
	oldLines := strings.Split(string(a), "\n")
	newLines := strings.Split(string(b), "\n")
	inNew := map[string]int{}
	for _, l := range newLines {
		inNew[l]++
	}
	inOld := map[string]int{}
	for _, l := range oldLines {
		inOld[l]++
	}
	var out []string
	for _, l := range oldLines {
		if inNew[l] == 0 && strings.TrimSpace(l) != "" {
			out = append(out, "    - "+l)
		}
	}
	for _, l := range newLines {
		if inOld[l] == 0 && strings.TrimSpace(l) != "" {
			out = append(out, "    + "+l)
		}
	}
	const maxLines = 200
	if len(out) > maxLines {
		out = append(out[:maxLines], fmt.Sprintf("    ... %d more lines", len(out)-maxLines))
	}
	return strings.Join(out, "\n"), nil
}

// compare checks one identity claim. ourRoot and theirRoot are prefixes for
// the manifest's relative paths; an empty ourRoot means the working
// directory, which is the module root.
func compare(id forks.Identity, ourRoot, theirRoot string) error {
	ours, err := forks.ReadFile(filepath.Join(ourRoot, filepath.FromSlash(id.Ours)))
	if err != nil {
		return fmt.Errorf("%s: %w", id.Ours, err)
	}
	theirs, err := forks.ReadFile(filepath.Join(theirRoot, filepath.FromSlash(id.Theirs)))
	if err != nil {
		return fmt.Errorf("%s: %w", id.Theirs, err)
	}
	a, b, err := extract(id, ours, theirs)
	if err != nil {
		return err
	}
	if a != b {
		what := id.Ours
		if id.Name != "" {
			what = id.Name + " in " + id.Ours
		}
		return fmt.Errorf("%s is documented as verbatim but differs from upstream's %s", what, id.Theirs)
	}
	return nil
}

func extract(id forks.Identity, ours, theirs []byte) (string, string, error) {
	switch id.Mode {
	case forks.ModeBytes:
		return string(ours), string(theirs), nil
	case forks.ModeCode:
		return forks.CodeOnly(ours), forks.CodeOnly(theirs), nil
	case forks.ModeFunc:
		a, err := forks.FuncText(ours, id.Name)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", id.Ours, err)
		}
		b, err := forks.FuncText(theirs, id.Name)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", id.Theirs, err)
		}
		return a, b, nil
	case forks.ModeBlock:
		a, err := forks.Block(ours, id.Name)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", id.Ours, err)
		}
		b, err := forks.Block(theirs, id.Name)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", id.Theirs, err)
		}
		return a, b, nil
	default:
		return "", "", fmt.Errorf("unknown identity mode %q", id.Mode)
	}
}

// advisories asks the OSV database which published advisories affect module
// at version, and keeps those whose affected import paths lie inside the
// copied ones. The filter is the point: x/crypto carries advisories about
// packages this module has never touched (openpgp, for one), and reporting
// them here would train the reader to ignore the job.
func advisories(module, version string, paths []string) ([]string, error) {
	type osvQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	var q osvQuery
	q.Package.Name = module
	q.Package.Ecosystem = "Go"
	q.Version = strings.TrimPrefix(version, "v")

	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv.dev returned %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Affected []struct {
				EcosystemSpecific struct {
					Imports []struct {
						Path string `json:"path"`
					} `json:"imports"`
				} `json:"ecosystem_specific"`
			} `json:"affected"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}

	var hits []string
	for _, v := range out.Vulns {
		for _, a := range v.Affected {
			for _, imp := range a.EcosystemSpecific.Imports {
				if !affectsFork(imp.Path, module, paths) {
					continue
				}
				hits = append(hits, v.ID+" ("+imp.Path+"): "+firstLine(v.Summary))
				break
			}
		}
	}
	return hits, nil
}

// affectsFork reports whether an advisory's affected import path is one of
// the copied packages, or inside one. An advisory listing no import path at
// all — a module-wide one — is not matched here: it would fire on every fork
// for a change in any package, and the paths are what was copied.
func affectsFork(importPath, module string, paths []string) bool {
	for _, p := range paths {
		full := path.Join(module, p)
		if importPath == full || strings.HasPrefix(importPath, full+"/") {
			return true
		}
	}
	return false
}

// die reports a failure of the tool itself — a manifest it cannot parse, a
// file it cannot write — which is not a drift report and must not be read as
// one, hence the distinct exit status.
func die(err error) {
	fmt.Fprintf(os.Stderr, "forkcheck: %v\n", err)
	os.Exit(2)
}

func writeJSON(w io.Writer, results []result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeJSONFile(name string, results []result) error {
	//nolint:gosec // G302/G304: a report written where the caller asked, with
	// the default mode a CI artifact needs; it holds no secret.
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	if err := writeJSON(f, results); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// writeCounts appends the two tallies in key=value lines, which is what a
// GitHub step writes to $GITHUB_OUTPUT. Appending, not truncating: that file
// may already hold another step's outputs.
func writeCounts(name string, results []result) error {
	var drift, unknown int
	for _, r := range results {
		switch r.Status {
		case "drift":
			drift++
		case "unknown":
			unknown++
		}
	}
	//nolint:gosec // G302/G304: two integers appended to the file the caller
	// named, which in CI is $GITHUB_OUTPUT.
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "drift=%d\nunknown=%d\n", drift, unknown); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// report renders the human-readable form. It returns the text rather than
// writing it so that the only output call in this command is one checked
// fmt.Print: a report that half-printed and swallowed the error would be a
// quiet version of the silence this tool exists to break.
func report(results []result) string {
	var out []string
	add := func(format string, args ...any) {
		out = append(out, fmt.Sprintf(format, args...))
	}
	drift := 0
	for _, r := range results {
		switch r.Status {
		case "clean":
			line := fmt.Sprintf("ok      %-14s %s", r.ID, r.Upstream)
			if r.Newest != "" {
				line += " @ " + r.Newest
			}
			out = append(out, line)
		case "drift":
			drift++
			add("DRIFT   %-14s %s", r.ID, r.Upstream)
		default:
			add("unknown %-14s %s", r.ID, r.Upstream)
		}
		for _, f := range r.Findings {
			add("        %s", f)
		}
		for _, a := range r.Advisory {
			add("        advisory: %s", a)
		}
		if r.Stale != "" {
			add("        upstream is unchanged through %s, which the manifest does not record yet (-update writes it)", r.Stale)
		}
		if r.Diff != "" {
			out = append(out, indent(r.Diff, "        "))
		}
	}
	if drift == 0 {
		out = append(out, "", "every fork is at a point upstream has not moved past.")
	} else {
		out = append(out, "", fmt.Sprintf("%d fork(s) need a decision; see CONTRIBUTING.md \"Maintaining the forks\".", drift))
	}
	return strings.Join(out, "\n") + "\n"
}

func indent(s, with string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = with + l
	}
	return strings.Join(lines, "\n")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func goEnv(name string) (string, error) {
	//nolint:gosec // G204: a fixed argv; name is one of this file's constants.
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", errors.New("go env " + name + " is empty")
	}
	return v, nil
}

func sha256URL(url string) (string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 64<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
