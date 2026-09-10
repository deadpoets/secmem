# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version is `0.x`, the public API may change between minor versions as
the surface settles; breaking changes will be called out here. `1.0.0` will
mark the stability commitment.

## [Unreleased]

> This repo holds three independently versioned Go modules; entries are tagged
> by module. Untagged entries belong to the core `secmem` module.

### Added

- **Independent oracles for claims that rested on a syscall's return value,
  and a CI that cannot pass over a skipped proof.** On Linux the lock, dump,
  fork and THP flags are now read back from the kernel's own `/proc/self/smaps`
  record on both allocation tiers, and the KSM opt-out is proven under
  `PR_SET_MEMORY_MERGE` in the new root lane, which also repeats the
  `memfd_secret` extraction proof as root with every environmental skip turned
  into a failure. On Windows the process mitigations are read back through
  `GetProcessMitigationPolicy`, and the WER registration through WER's own
  unregister result. The region wipe itself is fuzzed
  (`FuzzWipe_RegionReadsBackZero`: `Truncate`, `WipeAllSecrets`, slot
  release, read back as zero). Every test step runs through
  `internal/skipaudit`, which prints each skip with its reason and fails the
  job on any skip not on the lane's allowlist; the vector-clear proof's
  control is pinned to `Scrub`'s source; the stub platforms are
  compile-checked; and `secmem-crypto` and `secmem-lint` are built and tested
  against their released dependencies on every PR. Test and CI changes only —
  no library code changed. Where a proof does not exist the wording now says
  so: the WER exclusion is reported by the registration call, not verified by
  a dump, and the wipe's cache flush is structural, not measured.

- **`secmem-crypto`: `BcryptPBKDFInto` — OpenSSH's bcrypt_pbkdf as a KDF in
  its own right.** The algorithm lives in `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf`,
  where nothing outside x/crypto can call it, so a program that has to
  reproduce ssh-keygen's derivation — opening or writing a key file's
  protection by hand, or matching a derivation performed elsewhere — had to
  vendor it. This module already carries a wiping fork for its own passphrase
  paths; the new function is that fork behind the same `*Into` shape the rest
  of the KDFs use, deriving `out.Len()` bytes — up to `MaxBcryptPBKDFKeyLen`,
  upstream's 1024 — into a `SecureBuffer`. Nothing
  holding secret state touches the heap: the whole working set is one locked
  workspace allocated for the call and wiped before it returns. The doc says
  plainly that this is an interoperability primitive and not the password KDF
  to choose fresh — bcrypt_pbkdf's working set is a 4 KiB Blowfish schedule
  whatever cost you ask for, so `Argon2Into` is the memory-hard answer.

- **`secmem-crypto`: the OpenSSH passphrase cost is configurable.**
  `Ed25519Signer.MarshalOpenSSHPrivateKeyWithPassphraseParams` takes
  `OpenSSHPassphraseParams{Rounds}` — ssh-keygen's `-a` — where the existing
  method always wrote ssh-keygen's default of 16, now exported as
  `OpenSSHKDFRounds`. Rounds are capped at `MaxOpenSSHKDFRounds` (2048), and
  the cap is there for one reason: `x/crypto/ssh` and this package's own
  parser both refuse a file above it, so writing higher would produce a file
  nothing could open. A test anchors that constant to x/crypto's own maximum
  rather than to itself, so the two cannot drift apart unnoticed. A higher
  cost buys time-hardness only, which the doc says plainly.

- **`secmem-crypto`: `ErrRetiredAlgorithm` separates a refusal that is a
  decision from one that is a gap.** Both looked identical to a caller: an
  error wrapping `ErrUnsupportedKey` could mean "convert your file" or "wait
  for a release", and the only way to tell was to read the message. Legacy
  PEM encryption (the `Proc-Type` / `DEK-Info` headers, whatever cipher they
  name) now wraps this marker as well as the sentinel it already wrapped, and
  the error from either entry point says which command rewrites the file. It
  will not gain support:
  the key comes from one pass of MD5 over the passphrase and an 8-byte salt,
  so there is no cost to raise, and the ciphertext is unauthenticated CBC.
  Keeping such a file openable is what lets it stay unconverted. Refusals
  that are only unimplemented — PBES2, `chacha20-poly1305@openssh.com`,
  aes128/192 — deliberately do not wrap it, and a test enforces that
  distinction so the marker cannot decay into a synonym.

- **`ADOPTION.md`, and two more pitfalls.** An adoption guide for putting the
  library into an existing service: inventory the secrets, classify each as
  INTERNAL (the plaintext never leaves a buffer) or EXTERNAL (it must cross
  out, so the job is one short-lived copy per crossing and a written residual),
  draw the boundary map of crossings against the helpers that handle them, and
  size the locked-memory budget with a formula over buffers, arenas,
  workspaces and transients. `PITFALLS.md` gains a secret inside a decoded
  JSON document (a field type that unmarshals straight into a buffer, and why
  `json.NewDecoder` and `io.ReadAll` defeat it) and writes to globals or
  caches inside a `Scrub` window. Documentation only.

- **`secmem/redact`: `Handler` redacts by attribute KEY, not only by value.**
  `slog.String("password", "hunter2")`, `logger.With("token", t)`,
  `slog.Group("db", slog.String("password", …))` and a `[]byte` or struct
  under a `client_secret` key all reached the sink in full, because the
  handler only ever looked at values and `hunter2` on its own has no
  credential shape. An attribute whose key is in the sensitive set now has
  its whole value replaced with `[REDACTED:key]` whatever its kind — string,
  bytes, number, group (as a whole), Any, or an unresolved `LogValuer`. Keys
  are compared case-insensitively as a whole and as components split on
  `_`, `-`, `.`, `/`, digit runs and CamelCase, so `DB_PASSWORD`,
  `db.password`, `accessToken` and `x-api-key` all match, and a
  multi-component entry such as `api_key` matches across a `WithGroup("api")`
  and a `key` attribute. A `WithGroup` whose name is sensitive redacts every
  attribute beneath it. `DefaultSensitiveKeys` lists the set (password,
  passwd, pwd, pass, passphrase, secret, token, access/refresh/id_token,
  api_key, authorization, auth, bearer, cookie, set_cookie, session,
  private_key, signing_key, credential(s), client_secret and a few more);
  `WithSensitiveKeys` extends it and `WithoutDefaultSensitiveKeys` drops the
  defaults. `NewHandler` takes the options variadically, so existing calls
  compile unchanged.

- **`secmem/redact`: `Rule.Filter`, and `Rule.Tag` documented as a template.**
  A `Filter func(match string) bool` on a rule vetoes individual matches, for
  heuristics a regex cannot express; the built-in base64 rule uses it. `Tag`
  has always been passed through `ReplaceAllString`, which expands `$1`; that
  is now documented, and the new URL rules rely on it to keep the part of a
  match that is not the credential.

- **`secmem/httpauth`: `ForceHTTP1`.** Returns a clone of an `*http.Transport`
  (or of `http.DefaultTransport`) that negotiates HTTP/1.1 only —
  `ForceAttemptHTTP2` off, an empty `TLSNextProto` map, `h2` dropped from the
  TLS config's ALPN list — for callers who want the credential kept out of
  HTTP/2's per-connection HPACK dynamic table. The package doc's residual list
  now states that table precisely: the bundled http2 client inserts every
  header field, `authorization` included, into the 4 KB table without marking
  it sensitive, where it lives until evicted or the pooled connection closes,
  and the encoder's scratch buffer holds it until the next request. The list
  also gains the HTTP/1 header writer's pooled sorter (the `[]string` holding
  the value stays reachable from a `sync.Pool` until the next header write
  anywhere in the process) and `httptrace.WroteHeaderField`. A test proves
  the recipe produces an HTTP/1.1 request against an h2-enabled server.

- **`secmem-lint`: the escape check follows the bytes, not just the
  identifier.** A borrowed slice now taints every local derived from it —
  aliases, elements, conversions (`any(b)`, `[]byte(b)`), composites
  (`holder{b}`, `msg{b}` on a channel, `&myErr{b}` returned), element-wise
  copy loops, closures that capture it, `unsafe.String` / `SliceData` /
  `Pointer`, `reflect.ValueOf`, `bytes.NewReader` — and a finding fires
  where a tainted value reaches memory outside the closure. The accessor call
  is resolved through more shapes too: a closure held in a local assigned
  once, a package-level function passed by name, a method value
  (`f := buf.WithBytes`), an interface receiver with a borrowing-shaped
  method, and a `type raw = []byte` parameter. `-strict` now also reports a
  closure it cannot resolve, so coverage gaps are visible instead of silent.
  The sink table gains `os.WriteFile`, the `Write` methods of `bytes.Buffer`
  / `strings.Builder` / `bufio.Writer` / `os.File`, the `json` / `xml` /
  `gob` decoders, `hex.Dump` / `AppendEncode`, `base64` / `base32`
  `AppendEncode`, `slices.Concat`, `bytes.Join` / `Repeat`, `slog.Any` /
  `String` / `Group` and `Logger.With`, the `testing` log methods, and the
  stdlib / `x/crypto` ciphers, key parsers and KDFs that copy a key into heap
  state. `io.Writer` / `net.Conn` interface values stay unflagged by design.
  Reentrancy resolves aliases (`b2 := buf`) and method values (`l := buf.Len`),
  and covers `ArenaSlot.Release` and the arena's exclusive-lock methods
  (`Destroy`, `ReadOnly`, `ReadWrite`) inside a slot borrow.

- **`secmem-crypto`: every entry point is classified, and the README says
  what each signer buys you.** The module's headline claimed key material
  stays in a `SecureBuffer` "for the whole of the operation"; that is true of
  Ed25519 signing, the parsers, the KDFs and AEAD helpers that write in
  place, and false — admitted a paragraph later — of everything that hands a
  copy to a standard-library primitive. The README now carries a class per
  entry point (**contained**, or **runtimesecret-only**: contained on
  linux/amd64|arm64 with `GOEXPERIMENT=runtimesecret`, transient on the heap
  everywhere else), a table of what is protected at rest and what copies
  each operation leaves on each kind of build after the fixes below, and a
  recommendation on `RSASigner` and `ECDSASigner` for legacy builds.
  `classification_test.go` pins the classes: `SealFrom` at zero allocations,
  `Ed25519Signer.Sign` at exactly one (the signature) for messages up to
  4 KiB, the standard-library-backed paths as allocating.

- **`secmem-crypto`: `ErrHeapTransients`, an unused gate.** The constructors
  of `RSASigner` and `ECDSASigner` consult a package-level policy that is
  permissive in this release. Flipping it to `secmem.RuntimeSecretActive`
  refuses both types with this error on any build where their per-operation
  heap copies are never erased; the decision is recorded in the README and
  left to the maintainers, and the error exists now so callers can test for
  it before it is ever returned.

### Changed

- **`secmem/httpauth`: the credential is no longer sent over cleartext http
  unless the caller opts in.** `Transport.Hosts` compared only the host, so
  with `Hosts=["api.example.com"]` a plain `http://api.example.com/` URL, or
  an https→http redirect on that host, carried the bearer token in the clear.
  A request for an admitted host whose scheme is not https now fails with
  `ErrInsecureScheme` — it is not forwarded bare, because a silent 401 would
  hide the downgrade — unless `Transport.AllowInsecureHTTP` is set or the
  host is listed with an explicit scheme: `"http://localhost:8080"` admits
  cleartext for that host alone, `"https://api.example.com"` admits only TLS,
  and a bare entry admits https (and http only with the flag). The empty
  filter follows the same rule. A request to an unlisted host is still
  forwarded untouched. This breaks any caller that was injecting over plain
  http, which is the point; set `AllowInsecureHTTP` or an `http://` entry to
  keep doing it deliberately. A redirect test with a TLS server bouncing to a
  cleartext one pins the refusal.

- **`secmem/redact`: `Handler` renders `Any` values to one sanitized string.**
  A struct, map, slice, `[]byte`, `fmt.Stringer` or a `LogValuer` resolving
  to any of those used to pass through the handler untouched, carrying its
  secrets to both text and JSON sinks. Such a value is now rendered to a
  `%+v`-like text by a reflection walk — which applies the sensitive-key set
  to struct field names and map keys along the way and treats `[]byte` as
  text — then sanitized and emitted as a single string attribute. The
  structured shape is lost at the sink: a JSON handler writes a string where
  it used to write an object or array, and bytes as text rather than base64.
  Numbers, bools, times, durations and a nil `Any` are untouched.

- **`secmem/redact`: `WithMaxLen` truncates before the rules run.** The cut
  used to come after the rules on each pass, so it bounded the output but
  not the work. It now happens before the first pass (at a rune boundary),
  which is what makes the cap a bound on what a hostile input can cost, and
  again after each pass if the tags grew the result. `Sanitize` stays
  idempotent. The `pem_private_key` rule moves from `CommonProviderRules`
  to `DefaultRules` — the format is vendor-neutral — and the recommended
  order is now `append(CommonProviderRules(), DefaultRules()...)`, because
  the default base64 heuristic no longer needs `=` padding and would
  otherwise tag a real provider token as `base64_secret` first.

- **`secmem-lint`: the recommended idioms no longer report.** `copy` / `append`
  into another borrowed slice (the decrypt-into pattern, nested either way),
  into an array or struct declared inside the closure, or into a local slice
  made with `make` / a literal is not an escape; a func literal that calls the
  buffer but is only assigned or returned runs after the lease and is not
  reentrant; the slice's address as a `uintptr` is not the secret. The README
  and package doc now say exactly what the analyzer resolves and what it does
  not, and the `-strict` flag is documented in the form `go vet` accepts.

- **`secmem-crypto`: the legacy-PEM refusal from `ParsePrivateKey` is a
  wrapped error, not the bare sentinel.** A `Proc-Type` / `DEK-Info` file
  used to return `ErrEncryptedKey` itself; it now returns an error that wraps
  it, together with `ErrRetiredAlgorithm` and the conversion hint. `errors.Is`
  keeps working. A caller comparing with `==` stops matching for this one
  input — the other encrypted forms still return the bare sentinel — which
  is recorded here because no signature changed and `gorelease` cannot see
  it.

- **`secmem-crypto`: the Argon2 fork's own vector-register clear is gone, and
  so is the passphrase path's use of it.** The follow-up the v0.6.0 floor
  raise promised. Since core v0.5.0 every `Scrub` and `ScrubErr` window pins
  its goroutine and clears the vector file on the way out, so the fork's
  amd64 `VZEROALL`/`PXOR` helper, the `runtime.LockOSThread` pairs around
  its three windows and the temporary `argon2.ClearVectorRegs` export that
  `opensshCrypt` deferred were all a second copy of what the window already
  does. Nothing observable changes: the same registers are cleared at the
  same point, on the same thread, by the core's proven routine instead of
  the module's. The tests move with it — `scrubclear_amd64_test.go` shows
  the core's clear reaches what blamka and a whole `Derive` leave, and
  `vecclear_amd64_test.go` shows the same for the passphrase path inside
  the window its callers use, each with a bare-run control that must show
  residue. The test-only register probe moves to `internal/regprobe` so both
  packages can use it.

- **`Capabilities.Warnings` says what `VirtualLock` does not do.** On
  Windows a locked report now carries one more line: `VirtualLock` pins pages
  into the process working set, not into physical memory, and when the
  memory manager outswaps an idle process's working set as a whole, locked
  pages go to the pagefile with it. The README matrix cell, the package doc
  and the `Mlocked` field doc say the same; the `EnsureMemlockLimit` code
  records why the working-set minimum stays soft (a hard minimum does not
  reach locked pages, which the trimmer already skips).

- **Documentation corrections.** `DESIGN.md` and `PITFALLS.md` no longer say
  the garbage collector moves heap objects (it is non-moving for the heap, as
  `THREAT-MODEL.md` already said); the off-heap rationale is now the real
  one — heap pages cannot be locked, guarded or protected, the GC does not
  zero what it frees, and stacks *do* move. The cache-flush rationale is
  corrected the same way: caches are coherent, so the flush changes nothing a
  CPU read can see; it shortens the time the old bytes remain in DRAM, which
  matters only to DMA or cold-boot capture — out of the threat model, so the
  flush is defence in depth. The amd64 wipe is described as what it is
  (`REP STOSB` and fences, not non-temporal stores); the package doc no
  longer calls the wipe "architecture-specific assembly" on every platform;
  and the `SecureBuffer` header lists every method that takes the exclusive
  lock instead of claiming only `Destroy` does.

- **`secmem-crypto`: `MLKEM768Key` wipes the expanded key, and the
  encapsulation key is cached.** The type doc said the seed "lives in a
  SecureBuffer for its entire lifetime" and only the expanded key touched
  the heap. In go1.26 that expansion — the `crypto/internal/fips140/mlkem`
  key `NewDecapsulationKey768` allocates — stores the seed halves d and z
  verbatim and the secret polynomial `s`, so every operation put the seed on
  the heap and left it there. The expansion is now wiped by reflection
  through its unexported fields after construction and after every
  `Decapsulate`, with a tripwire test pinning the layout (`dk.Bytes()` reads
  zero and the key no longer decapsulates afterwards) and a call that returns
  an error rather than succeeding over a live copy. The 1184-byte
  encapsulation key is public and is computed once at construction:
  `EncapsulationKeyBytes` no longer expands the seed, and — like
  `Ed25519Signer.Public` — keeps working after `Destroy` and while the seed
  is sealed, where it used to return `ErrDestroyed` / `ErrSealed`. The doc
  now names what still transits the heap: crypto/mlkem's SHA3/SHAKE states
  and the recovered message, erased by the runtime on a runtimesecret build
  and left to the collector elsewhere.

- **`secmem-crypto`: `RSASigner` wipes the standard library's FIPS-form
  key, and a wipe it cannot perform is an error.** The type doc said the
  unexported FIPS-form key inside `Precomputed` was "not reachable"; it is
  reachable the same way the AES schedule and the ECDH scalar already were,
  and it holds a second copy of every secret integer as `bigmod` limbs —
  d and qInv, p and q with the Montgomery constants derived from them, dP
  and dQ — which every `Sign` uses and nothing zeroed. `wipeRSAPrivateKey`
  now reaches it by reflection, with a tripwire test that uses
  `crypto/rsa`'s own `Validate` consistency check as the independent oracle,
  and returns an error when the layout is not the one it expects; `Sign`,
  `NewRSASigner` and `GenerateRSASigner` fold that error into their result
  instead of reporting success over a live key. The doc now lists what
  remains — the parse's `big.Int.Bytes()` copies, `Validate`'s comparison
  copies, and the signature's Montgomery scratch — and corrects the claim
  that `math/big` scratch is "left to `ScrubErr` and the collector":
  `math/big`'s division scratch is a `sync.Pool` returned unwiped, which
  stays reachable, so `runtime/secret` does not erase it either. Two-prime
  keys no longer touch it at all (next entry); a deprecated multi-prime key
  still does, and the doc says so.

- **`secmem-crypto`: an OpenSSH RSA key's CRT exponents are computed over
  stack arrays, not with `math/big`.** `pkcs1DER` derived dp and dq with
  `big.Int.Mod`, pushing limbs of d, p and q through the pooled scratch
  above. It now uses a shift-and-subtract reduction (`modreduce.go`, about
  a hundred lines, one conditional subtraction per bit of d, no
  value-dependent branches) over fixed-size stack arrays inside the parse's
  Scrub window, wiped before return; the differential test compares it
  against `math/big` on random operands across the accepted size range and
  the edges, and the parser's allocation proof now covers the OpenSSH RSA
  container it used to exclude. The DER is unchanged byte for byte.

- **`secmem-crypto`: Ed25519 signing assembles the nonce pre-image on the
  stack.** The 32-byte secret prefix and the message were concatenated into
  a heap slice (wiped) for every signature; for messages up to 4 KiB that
  now happens in a stack array inside the Scrub window, so a signature makes
  exactly one heap allocation — the signature. The file doc also corrects
  "the seed itself is never copied": it is copied twice on the stack inside
  `sha512.Sum512`, in frames the window wipes, and says why a streaming
  digest would be worse (a heap block buffer that `Reset` does not clear).

- **`secmem-crypto`: the parser and `ECDSASigner` docs are true.**
  `ParsePrivateKey` said only non-secret material touched the heap with one
  exception; every EC path ends in `ecdsa.ParseRawPrivateKey`, which builds
  a `bigmod.Nat` and a FIPS-form key holding the scalar before the `big.Int`
  the module wipes. The `ECDSASigner` doc now lists every copy `Sign` leaves
  in go1.26, including the FIPS-form key `crypto/ecdsa` keeps in a
  package-level weak-pointer cache until the collector evicts it — not
  reachable from any wipe, kept short-lived by not retaining the transient
  between operations, and named as the longest-lived residue on a legacy
  build.

### Fixed

- **`secmem/redact`: the allowlist was quadratic in the message.** Every
  entropy match re-scanned `message[:matchStart]` with every allowlist
  pattern. On the default configuration 41 KB took 0.85 s, 205 KB 22 s and
  410 KB 145 s. The allowlist is now indexed once per rule application (one
  `FindAllStringIndex` per pattern, then binary search per match): the same
  inputs take 33 ms, 160 ms and 320 ms. An allowlist match still exempts an
  entropy match that begins where it ends, and now also one it contains
  entirely. A scaling test and a 400 KB benchmark pin it.

- **`secmem/redact`: the default rules missed common credential shapes.**
  Verified against the previous rule set: `Authorization: Bearer <JWT>` and
  `Authorization: Basic …` (the auth rule needed `=`/`:` right after `auth`,
  and a JWT has no `=` padding for the base64 rule); `AWS_SECRET_ACCESS_KEY=…`
  (only the non-secret `AKIA…` id was caught); `passwd=`, `pwd=`, `pass=`,
  `passphrase=`, `secret_key=`, `private_key=`, `signing_key=`,
  `credentials=`; `postgres://user:PASSWORD@host`; `?code=` and other
  credential query parameters; `Cookie:`/`Set-Cookie:`; `0x` + 64 hex (`\b`
  does not fall after `x`); unpadded and base64url tokens; `password => x`;
  JSON-escaped `\"password\":\"x\"`; `password%3Dx`; `OPENAI_API_KEY=` (`\b`
  does not fall after `_`); and every body line of a PEM block, because the
  CRLF rule tagged the line breaks before the base64 rule ran and the PEM
  rule only ever matched the header. Each has a rule now — Authorization
  with any scheme, Cookie, URL userinfo and query, the extra key spellings,
  JWT, bare Bearer, a PEM rule that matches header through footer and runs
  before CRLF, a base64 rule that accepts unpadded and base64url runs
  (screened by a mixed-case-plus-digit filter so paths and identifiers stay
  put), and a hex rule that accepts `0x`. `CommonProviderRules` gains
  fine-grained GitHub PATs, GitLab PATs, OpenAI-style `sk-` keys, `ASIA`
  temporary AWS ids and the AWS secret key by name. Tests cover both
  directions: every shape above is redacted, and UUIDs, allowlisted commit
  hashes, module and file paths, long identifiers, `bypass=`, `token_type=`,
  `password_length=` and `Bearer authentication required` survive unchanged.

- **`Scrub` and `ScrubErr` now scrub the frames that were live when the
  callback panicked.** The legacy (non-`runtime/secret`) window ran its
  stack wipe from a deferred call. When the callback panics, the runtime
  runs deferred calls from `gopanic`'s frame, which sits *below* the frames
  still live at the panic; the 32 KiB wipe therefore landed under the
  residue, not on it. Measured: a callback filling 2 KiB at each of four
  recursion levels and panicking from the deepest left 2048/2048 marker
  bytes behind — identical to no `Scrub` at all. The window now runs the
  callback through a helper that recovers the panic, clears the vector file
  and burns the band once those frames are dead, then re-raises — so the
  panic appears to originate from `Scrub`, as `runtime/secret.Do` does.
  `runtime.Goexit` inside the callback remains best-effort and is documented
  as such. Regression test: `TestScrub_ScrubsLiveFramesOnPanic`.

- **A GC cleanup racing `WipeAllSecrets` can no longer strand a locked
  mapping.** The cleanup consulted the registry before taking the region's
  lock, while the wipe passes took the lock first and briefly held the region
  in *neither* set. A cleanup that looked in that window found nothing,
  returned, and was consumed for good; the pass then parked the mapping in
  the wiped set with no path left to reclaim it — a leaked, still-locked
  mapping until process exit. The passes now move the region between sets in
  one registry operation, and the cleanup peeks, locks, then re-resolves
  under its own exclusive lock, the same order the passes use. Regression
  test: `TestJanitorRelease_ConcurrentWithWipePass_ReclaimsMapping`, which
  forces the interleaving.

- **`ArenaSlot.WithBytes` checks the handle's generation under the region
  lock.** The check ran first and the lock was taken afterwards, so a
  borrower that passed it and then waited for the lock (any queued writer
  parks new readers) resumed holding a slice into a slot that had meanwhile
  been released, wiped, re-acquired and written by a new owner — and read or
  overwrote that owner's secret with no error. The check now runs after the
  lock, immediately before the slice is produced. A release that runs
  concurrently with the callback itself remains the single-owner rule's to
  prevent, as documented. Regression test:
  `TestArenaSlot_StaleHandleRefusedUnderLock`, which forces the interleaving.

- **Janitor registration keys are 64 bits wide end to end.** The key was
  minted as `uintptr(counter)`; on a 32-bit target that wraps after 2^32
  registrations, after which a new registration silently overwrote a live
  one and the older buffer's `Destroy` would have wiped and unmapped a
  different live buffer with no lock held. The maps, the owners' fields, the
  cleanup argument and `LockOrder` are `uint64` now, and a registration whose
  key is already in use (or zero) is refused with an error from the
  constructor rather than absorbed.

- **`Probe` no longer fires the "INSECURE fallback in use" warning on
  platforms without secure memory.** The warning fired from the stub
  allocator, which `Probe` uses to report what the platform provides; it now
  fires from the constructor gate, only when `WithInsecureFallback` is
  actually used.

## [0.5.0] - 2026-09-07

Two boundary-hardening pieces: `Scrub` and `ScrubErr` clear the vector
registers after every window, and `secmem/httpauth` injects a credential per
request from a `SecureBuffer` instead of keeping it in an `http.Header`.
Adds `Capabilities.VectorRegisterClear` and a package, hence minor.

### Added

- **`Scrub` and `ScrubErr` clear the vector registers after the callback
  returns.** Vectorised crypto keeps its working state in the vector file — an
  AES round key in XMM, a BLAKE2b or ChaCha state in YMM, an Argon2 block row
  in X0–X7 — and nothing in the Go runtime ever clears it, so on the legacy
  path the last values a window computed stayed readable in the registers of
  whichever thread ran it until something else happened to overwrite them. The
  frame wipe cannot reach registers, and `scrub_legacy.go` carried a TODO
  refusing any register scrub without an empirical test that it reaches the
  residue, because the ABI reloads general-purpose registers around the call
  that would clear them. Vector registers are different: the Go ABI treats
  every one as caller-saved scratch (X15 is a fixed zero, and re-zeroing it is
  harmless) and reloads none of them around a call, so a clear destroys
  nothing live and does reach what the callback left. Both `Scrub` paths now
  run one as the first deferred call after `fn` — normal return and panic
  unwind alike, before the frame wipe and before the thread pin is released:
  `VZEROALL` on amd64 (sixteen `PXOR`s without AVX) plus `VPXORQ` over
  Z16–Z31 where AVX-512 is present, since `VZEROALL` does not reach them, and
  `VEOR` over V0–V31 on arm64. On the `runtime/secret` path it is redundant
  belt-and-braces and says so. The clear needs the goroutine on the thread
  that holds the residue, so the window now pins with `runtime.LockOSThread`
  on Windows and Darwin as well, where before nothing was pinned; the pin is
  not a suppression and `AsyncPreemptSuppressed` stays false there — a
  preemption landing before the clear can still copy the register file into
  runtime buffers, which the clear does not reach. Proven, per the TODO's
  rule, by `scrub_vecclear_test.go` with a test-only `internal/regprobe`
  package (its own package because a `_test.s` is assembled into the
  production package): a non-zero pattern is planted in the registers inside
  a window and read back all zero after `Scrub`, `ScrubErr`, and a `Scrub`
  whose `fn` panics; a control that runs the window's exact exit sequence
  without the clear must show the pattern surviving, and a zero there is a
  failure, not a skip. The panic case is bounded honestly: after the clear
  the runtime's own stack walk to the next frame with defers copies its
  bookkeeping through one vector register (`runtime.(*unwinder).initAt`, 16
  bytes of X14 on go1.26), so the proof measures that footprint with a
  panicking control and requires zero everywhere outside it. Executed on
  windows/amd64 with AVX (no AVX-512, so the Z16–Z31 proof skipped there and
  runs on the CI runners that have it); the arm64 clear is compile-checked
  locally and proven only by the CI arm64 job. Not covered, unchanged:
  general-purpose registers on the legacy path. Reported as
  `Capabilities.VectorRegisterClear` (`vector-clear` in `String`), with a
  warning when neither it nor `RegisterScrub` is in force. Adding a field is
  exported API, so the next core release is a minor bump. `secmem-crypto`'s
  Argon2 fork carries its own copy of the amd64 clear from before this
  landed; it can drop it once it requires the core release that includes it.

- **`secmem/httpauth` — an `http.RoundTripper` that injects the credential
  per request from a `SecureBuffer`.** Every cloud SDK and API client takes
  its token as a `string` and keeps it for the client's lifetime, which puts
  the secret on the GC heap — unlocked, unwiped, dumpable — for the life of
  the process. `httpauth.Transport` holds the token in a `SecureBuffer` and
  builds the header value on each request: `NewBearer` for `Authorization:
  Bearer`, `NewHeader` for any header and prefix (`X-API-Key`), `NewBasic`
  for RFC 7617 with the password never becoming a string of its own. The
  value is assembled in wiped scratch inside a `ScrubErr` window, so on a
  runtime/secret build the runtime erases it once unreachable, and the
  header is deleted from the sent request as soon as the base transport
  returns, whether it succeeded or not. The caller's request is never
  modified. The residual, stated in the package doc as plainly as
  `ExposeString` states its own: the per-request string is unavoidable and
  cannot be wiped, only made unreachable early; the bytes in the connection's
  write buffer and TLS records are out of reach. Also documented, and tested
  in both directions: the transport sits below `http.Client`, so the Client's
  rule of dropping `Authorization` on a cross-domain redirect does not cover
  what is injected here — with no host filter the credential follows a
  redirect to the other host. `Hosts` is the answer; the constructors take it
  as their trailing argument so the example form, `NewBearer(tok, nil,
  "api.example.com")`, is the safe one. Adding exported API makes the next
  core release a minor bump.

### Changed

- **Guard-page fault proofs run out-of-process.** Recovering a hardware fault
  in-process trips a Go runtime bug on windows/amd64 with AMX-capable CPUs
  ([golang/go#81238](https://github.com/golang/go/issues/81238)): the OS
  exception frame overruns the goroutine stack and corrupts the heap below it,
  which is what the Windows CI job's two crashes were. Each probe now faults in
  a re-exec'd child and is proven by the runtime's own `unexpected fault
  address` report at the announced address, not by the child merely dying;
  two control cases pin that. Test harness only — `SetPanicOnFault` is armed
  nowhere in library code, so using secmem was never affected. The daily
  Windows soak workflow, which existed to sample the crash, is retired. Scope
  and evidence in `WINDOWS.md`.

## [secmem-crypto/v0.6.0] - 2026-09-07

The ingress: private-key files parsed into locked memory, unencrypted
(`ParsePrivateKey`) and passphrase-protected (`ParsePrivateKeyWithPassphrase`,
on an in-tree fork of OpenSSH's bcrypt_pbkdf that wipes its working state),
with the matching encrypted egress. Minor: new API, and the core floor rises
to v0.5.0.

### Added

- **`secmem-crypto`: `ParsePrivateKey` — private-key files parsed into
  locked memory.** The module had an egress (`MarshalOpenSSHPrivateKey`) and
  no ingress: loading an existing key meant `pem.Decode` plus
  `ssh.ParseRawPrivateKey` or `crypto/x509`, which materialise the whole
  key on the heap twice — the decoded DER and the parsed `*PrivateKey` with
  its `big.Int` limbs — where nothing can wipe either. `ParsePrivateKey`
  accepts OpenSSH (`ssh-ed25519`, `ecdsa-sha2-nistp{256,384,521}`,
  `ssh-rsa`), PKCS#8 (RSA, EC, Ed25519), SEC 1, and PKCS#1, PEM or raw,
  and returns the matching `Ed25519Signer`, `ECDSASigner`, or `RSASigner`
  behind a new `Signer` interface. The base64 body is decoded straight into
  a `SecureBuffer`, the container is read in place with zero-copy cursors
  (cryptobyte for ASN.1, a twelve-line reader for the SSH wire format), and
  the secret is copied exactly once, into the buffer the signer owns; the
  public key every OpenSSH file (and SEC 1 / PKCS#8 v2 optionally) carries
  is checked against the one derived from the private half. Passphrase-
  protected files return `ErrEncryptedKey` rather than a leaky decrypt —
  bcrypt_pbkdf and PBKDF2 are KDFs whose working state this module does not
  yet control; DSA, FIDO, certificate, X25519, and unknown-curve keys return
  `ErrUnsupportedKey`; errors never quote the input. The one heap exception
  is stated in the doc: an OpenSSH-format RSA key lacks the CRT exponents
  PKCS#1 needs, so dp and dq are computed with `math/big` and wiped limb by
  limb, with `math/big`'s own scratch left to the enclosing `ScrubErr`
  window; the assembled DER is byte-identical to
  `x509.MarshalPKCS1PrivateKey`'s and pinned as such. The claim that the
  parser itself allocates nothing secret is proven, not asserted: a test
  runs the memory profiler at rate 1 over every non-RSA-OpenSSH encoding
  and fails on any allocation owned by the parser's files, and it was shown
  to fail on an injected `bytes.Clone` of the seed. Round-trips are against
  what the standard library and x/crypto write, every proper prefix of a
  raw container is rejected, and a fuzz target requires any input that
  parses to yield a self-consistent signer. Minor bump for `secmem-crypto`;
  no floor change.

- **`secmem-crypto`: `ParsePrivateKeyWithPassphrase` and
  `MarshalOpenSSHPrivateKeyWithPassphrase` — passphrase-protected OpenSSH
  key files, in and out, on a KDF that wipes.** `ParsePrivateKey` refused
  protected files because opening one meant x/crypto's bcrypt_pbkdf, which
  leaves the passphrase in a heap SHA-512 digest, a 4 KiB Blowfish key
  schedule derived from it on the heap for every one of its bcrypt steps
  (32 of them at ssh-keygen's defaults), and the derived key and IV in a
  slice the caller cannot wipe. The KDF is now an in-tree fork,
  `internal/bcryptpbkdf` — x/crypto v0.56.0's `ssh/internal/bcrypt_pbkdf`
  and the `blowfish` it needs, BSD-3-Clause, provenance in `NOTICE`, every
  change listed in its package doc — with its whole working state in a
  caller-owned workspace: the Blowfish schedule is re-keyed in place, the
  SHA-512 steps are one-shots, the output goes into a caller slice. Output
  is pinned by OpenBSD's reference vectors (upstream's own, checked to be
  identical to upstream's), a differential test of the schedule against
  `x/crypto/blowfish`, and an identity test against the resolved x/crypto.
  `ParsePrivateKeyWithPassphrase` opens what ssh-keygen and x/crypto/ssh
  write (bcrypt, aes256-ctr or aes256-cbc, up to x/crypto's cap of 2048
  rounds): the container goes into a SecureBuffer, the private block is
  decrypted into a second one and handed to the same per-type extraction as
  the plain path, and the KDF workspace, the key and IV, and the cipher's
  scratch live in a third. The AES modes are written out over one
  `cipher.Block` rather than taken from `crypto/cipher`, whose CTR and CBC
  objects each copy the round keys into a second unreachable heap object;
  the one Block `crypto/aes` allocates has its schedule wiped by reflection,
  with a tripwire test that fails on a toolchain where the fields move and a
  call that fails closed rather than leave the schedule behind. After the
  SHA-512 and AES steps the vector registers are cleared through the Argon2
  fork's helper, pinned to the thread, until the module's core floor reaches
  the release that clears them in `Scrub` itself. A wrong passphrase is
  `x509.IncorrectPasswordError`, as in x/crypto; an unprotected file is the
  new `ErrNotEncrypted`; chacha20-poly1305, the aes128/192 variants, PKCS#8
  PBES2 and legacy PEM encryption are `ErrUnsupportedKey`. Tested against
  files a real ssh-keygen wrote (every key type, CBC, the default profile;
  fixtures in `testdata/openssh-encrypted`) and x/crypto's encryptor, with
  a fuzz target. `MarshalOpenSSHPrivateKeyWithPassphrase` writes the profile
  ssh-keygen uses by default (aes256-ctr, bcrypt, 16 rounds, a fresh
  16-byte salt), assembled and encrypted in place; ssh-keygen and
  x/crypto/ssh open the result, and the suite runs the real ssh-keygen on
  it where installed. Both paths are proven to put nothing on the heap but
  the AES Block, by the memory-profiler proof `ParsePrivateKey` introduced;
  during development it caught three leaks that would otherwise have
  shipped under this entry — CTR's keystream and counter escaping to the
  heap through the `cipher.Block` interface, the reflection lookup
  allocating per call, and a cipher name boxed by an error formatter. Minor
  bump for `secmem-crypto`; no floor change.

### Changed

- **Requires core v0.5.0.** Every `Scrub` window this module opens — the
  signers', the KDFs', the private-key parser's and the passphrase paths' —
  now clears the vector registers on the way out, from the core rather than
  from this module's own helpers. The Argon2 fork's amd64 clear and the
  passphrase path's use of it are now redundant and are removed in a
  follow-up; nothing observable changes. A dependency-only floor raise is a
  minor bump here, as this module's versioning note explains.

- **`secmem-crypto`: `MarshalOpenSSHPrivateKey` assembles the file in
  place.** It went through `ssh.MarshalPrivateKey` and `encoding/pem`, and
  its doc named the copies that route leaves unreachable: x/crypto's marshal
  scratch and padded key block, and base64's 1 KiB encoder window holding
  an armoured window of the key. The container is now written straight from
  the seed buffer into a SecureBuffer and the PEM armour into the returned
  one, by writers that allocate nothing; the output is byte-identical in
  layout to `encoding/pem`'s and checked as such, and ssh-keygen reads it.
  Behaviour and API are unchanged.

## [secmem-crypto/v0.5.0] - 2026-09-07

Argon2 that wipes its working state, on an in-tree fork of `x/crypto/argon2`,
plus a locked, reusable workspace for it. Minor: new API, no floor change.

### Added

- **`secmem-crypto`: `Argon2Into` and `Argon2Params` — Argon2 that wipes its
  working state.** `golang.org/x/crypto/argon2` leaves the whole derivation
  footprint behind: the 64 MiB matrix on the heap, the pre-hash H0, a scratch
  block per worker goroutine on that goroutine's stack, and a heap BLAKE2b
  digest whose block buffer holds the raw password after `Sum` and after
  `Reset`. No wrapper reaches it — `runtime/secret.Do` (so `secmem.Scrub`)
  does not extend to goroutines the wrapped function spawns, and erases heap
  only when the collector gets to it. `secmem-crypto/internal/argon2` is a
  fork of x/crypto v0.56.0 (BSD-3, see `NOTICE`) in which every piece of
  working state lives in one parent-owned workspace, wiped with
  `SecureWipe` before the call returns; H0 and H' are stack-only BLAKE2b
  for every output length (x/crypto's one-shots plus a forked portable
  finalisation); every worker goroutine runs its segment inside a `Scrub`
  window of its own, so a runtime/secret build erases worker stacks and
  registers and does not preempt them mid-block; and on amd64 the vector
  registers are cleared inside every window on the pinned thread (with an
  empirical register-dump test, per the rule in `scrub_legacy.go`). Output
  is byte-identical to upstream: pinned by the RFC 9106 §5 vectors for all
  three variants, a 24-case table and a differential fuzz target against
  x/crypto, and the forked assembly and verbatim functions are checked
  against the resolved x/crypto so a Dependabot bump that changes them goes
  red. The new function exposes the RFC's secret key K and associated data
  X, and the Argon2d variant, none of which x/crypto's public API can
  express. What is not covered is stated in `Argon2Into`'s doc: the
  workspace is pageable, dumpable heap for the call's duration and is not
  registered with secmem (`Argon2Workspace`, below, is the locked form), and on the
  legacy Scrub path an asynchronous preemption's copy of a worker's
  registers in runtime buffers is out of reach. Cost: the wipe is one
  cache-flushing pass over the working set, 5.5 ms for 64 MiB on a 2025
  desktop where the derivation takes 29 ms, so about a fifth more there and
  proportionally less on slower hardware (`BenchmarkForkVsUpstream`).
  Requested by secmem's second consumer; the brief and its fact-check are in
  the PR.

- **`secmem-crypto`: `Argon2Workspace` and `Argon2Pool` — Argon2 with its
  working state in locked memory, reused across calls.** `Argon2Into` wipes
  after the call but runs on pageable, dumpable, unregistered heap during
  it. A workspace puts the whole working set (matrix, lane scratch, H0, the
  H0 input holding the password and pepper) in one `SecureBuffer`: locked,
  guard-paged, dump-excluded where the platform allows, and registered so
  `WipeAllSecrets` and the termination wipe cover it. It is reused because
  a locked 64 MiB mapping costs more to create (14 ms) and destroy (24 ms)
  than the derivation (29 ms); between uses it holds zeros, wiped with the
  cache-flushing wipe whether or not the derivation succeeded. A pool holds
  a fixed number for concurrent callers, which is also the ceiling on
  in-flight derivations and locked memory. Neither falls back to the heap:
  a lock budget that cannot hold them fails at construction, before the
  first login, so a program's posture is decided where it can be seen
  (raise the budget with `EnsureMemlockLimit` at startup). Both borrow the
  workspace and the output in ascending `LockOrder`, the module's
  two-buffer rule. A non-flushing wipe for the between-use pass was
  measured (1.0 ms against 6.3 ms at 64 MiB) and not adopted: it leaves
  old contents under cached zero lines for as long as an idle workspace
  sits, and nothing short of a timer closes that. Measured at the package
  defaults on a 2025 desktop: x/crypto 30 ms, `Argon2Into` 35 ms, a reused
  workspace 35–38 ms, a workspace created and destroyed per call 68 ms
  (`BenchmarkArgon2_HeapVsWorkspace`). The workspace buys residence, not
  speed; reuse is what keeps it from costing double.

### Changed

- **`secmem-crypto`: `Argon2IDKeyInto` and `Argon2DeriveInto` now run on
  the in-tree fork.** Same signatures, same bytes out; the heap caveat in
  their documentation is gone because the residue it described is. The
  output buffer is now borrowed (the shared read lease of `WithBytesErr`)
  for the whole derivation rather than for a copy at the end, since the tag
  is computed in place: writers to it block for the derivation, and a
  concurrent reader would see the old or a partly written tag, so do not
  read it from another goroutine mid-derivation. Callers who wrapped the
  call in `ScrubErr` on the old doc's advice should remove the wrapper (see
  `Argon2Into`). `golang.org/x/sys` becomes a direct dependency of
  `secmem-crypto` (the fork's CPU-feature check; it was already indirect
  via x/crypto).

## [secmem-crypto/v0.4.0] - 2026-09-07

The review's crypto rows, plus the floor raise to core v0.4.0 and the switch to
`SecureBuffer.LockOrder` for lock ordering. Minor: the dependency floor moved.

### Changed

- **Requires core `secmem` v0.4.0.** The floor rises for `SecureBuffer.LockOrder`,
  which `X25519Key.ConstantTimeEqual` now orders its locks by (see Fixed).

- **`secmem-crypto`, `examples`: `golang.org/x/crypto` 0.54.0 → 0.56.0.**
  Maintenance, not a fix: the `vuln` job was green against 0.54.0, so nothing
  outstanding was reachable. Recorded because a `require` change in
  `secmem-crypto` raises the floor for everyone importing it, which is the same
  reason `secmem-crypto/v0.3.1` was a dependency-only release with an entry of
  its own.

  0.56.0 declares `go 1.26.0`, so both go directives moved with it. The two
  modules have to move together. `examples` pins `secmem-crypto` with a
  `replace`, but a replace does not exempt the `require` line from minimum
  version selection: bumping only `secmem-crypto` makes MVS select the newer
  version for `examples` too, while `examples/go.mod` still asks for the old
  one — and CI runs readonly, so that is a hard error before any package loads.

### Fixed

- **`X25519Key.ConstantTimeEqual` no longer deadlocks on a reversed comparison.**
  The same defect as the core's `Secret.ConstantTimeEqual`: both read locks were
  taken in argument order. It now acquires in a fixed global order by
  `SecureBuffer.LockOrder`, the process-unique ordinal the core exports as of
  v0.4.0 — which is why this module's floor rises with it.

- **`HKDFInto` now performs the Extract step inside its scrub window.**
  `hkdf.New` computes the PRK — `HMAC(salt, secret)`, key-equivalent for every
  byte Expand goes on to produce — and it was called *outside* the
  `secmem.ScrubErr` window the doc says wraps the derivation. The single most
  sensitive intermediate was the one value the window did not cover.

- **`MarshalOpenSSHPrivateKey` no longer claims to wipe copies it cannot
  reach.** The comment said "this copy, and every derived form below, is wiped";
  in fact only the forms this package holds a reference to are —
  `ssh.MarshalPrivateKey` builds its own intermediates around the private key
  and returns only the final slice. The claim now names its limit. The PEM step
  also encodes into a pre-grown buffer instead of `pem.EncodeToMemory`, whose
  growing `bytes.Buffer` orphaned an unwiped array holding a prefix of the
  base64-encoded private key on every reallocation.

- **`secmem-crypto` fails loud where a wipe or an in-place decrypt cannot be
  proven.** Three hardening fixes: the reflection-based ECDH-scalar wipe now
  returns an error — and a test tripwire fails on a toolchain field rename —
  instead of silently no-opping; diceware word selection reads the whole wordlist
  on every draw, so the choice is no longer a secret-dependent memory access, and
  the chosen words are written straight into a `SecureBuffer` rather than a heap
  `[]string`; and `OpenInto` verifies the AEAD wrote in place, wiping the stray
  heap plaintext and returning an error instead of silently succeeding with an
  unwritten buffer when it did not.

## [0.4.0] - 2026-09-07

The external security review, closed. Its one HIGH and every MEDIUM landed in
the train PRs; this release also carries the long tail of LOW and INFO findings,
each fix paired with a regression test shown to fail against the unfixed code —
except two where nothing observable from Go exists to test: the `memfd_secret`
close-on-exec flag (the descriptor is closed before the constructor returns)
and the placement of HKDF's Extract step inside its scrub window. Both are
listed under "Deliberately not proven" in `TESTING.md`.
Adds `InstallTerminationWipeNoExit` and `SecureBuffer.LockOrder`, hence minor.

### Changed

- **`release.sh` now refuses a stale in-repo dependency instead of passing it.**
  The ordering check only asked whether the required version was *published*.
  The failure it exists to prevent — the permanently inert
  `secmem-crypto/v0.3.0` — required a version that was published perfectly well;
  it was simply the previous one, because the tag was cut before the floor-raise
  PR merged. The gate therefore reported success on exactly the case it was
  written to catch. It now also requires that version to be the newest published
  one, fails closed when the proxy cannot be reached, and honours
  `SECMEM_ALLOW_STALE_DEP=1` for a deliberately older floor.

- **Nightly fuzzing covers every package and preserves failing inputs.** Targets
  were listed in the module root only, so `redact.FuzzSanitize` never ran, and a
  crash or hang input died with the runner — the reason a 2026-09-04
  `FuzzArgon2Params` timeout could not be diagnosed. The workflow now walks all
  packages and uploads any new `testdata/fuzz` input as an artifact.
  `staticcheck` is pinned to `2026.2.1` rather than tracking `latest`.

### Added

- **`InstallTerminationWipeNoExit`** — `InstallTerminationWipe` without the
  forced exit, for callers whose own handler owns termination. Adding exported
  API makes the next core release a minor bump.

- **`SecureBuffer.LockOrder`** — a process-unique, lifetime-stable ordinal.
  A caller that must hold two buffers' locks at once (a constant-time comparison
  of two secrets) can acquire them in ascending ordinal and never deadlock
  regardless of argument order. It lets `secmem-crypto` retire its address-based
  lock ordering, and the "sound while the GC does not relocate heap objects"
  caveat with it, at its next floor raise.

### Fixed

- **`Secret.ConstantTimeEqual` no longer deadlocks on a reversed comparison.**
  It took its two read locks in argument order, so `a.ConstantTimeEqual(b)` and
  `b.ConstantTimeEqual(a)` running concurrently acquired them in opposite
  directions; the writer-preferring lock makes the cycle routine (a `Destroy` or
  an emergency wipe queues a writer), and once wedged both buffers are
  unreachable for `Destroy` and `WipeAllSecrets` too. It now acquires in a fixed
  global order by `janitorKey`, a process-unique counter that assumes nothing
  about object placement — the ordinal `SecureBuffer.LockOrder` now exports.

- **Constructors now wipe the caller's input on failure, not only on success.**
  `NewBuffer`, `NewSyscallSafeBuffer` and `NewSecret` warn that the input is
  zeroed and must not be reused — but every error path returned with the
  plaintext intact. A caller following the warning does not wipe it themselves,
  so an allocation failure left the secret in an ordinary heap slice they
  believed was gone. The wipe is now deferred so future error paths cannot forget
  it. A retry after `ErrNoSecureMemory` therefore has nothing left to copy, and
  does not need one: that error depends only on the platform and on
  `WithInsecureFallback`, both knowable up front via `Probe`.

- **`Scrub`'s "nothing sensitive is on the abandoned copy" was false.** The entry
  wipe orders the stack growth, but `morestack` copies the *whole* stack, so the
  abandoned segment carries whatever the CALLER already had on its stack — a key
  in a local, or residue from an earlier operation — and returns to the stack
  pool unwiped, unreachable from Go. Added to the documented limits rather than
  left as a claim. Also corrects the stale "a no-op on other architectures",
  which has not been true since `scrubframe_arm64.s` landed.

- **`InstallTerminationWipe` now terminates the process on Windows instead of
  wiping and running on.** `os.Process.Signal` there implements only `os.Kill`
  and rejects `os.Interrupt` and SIGTERM, and the console event that triggered
  the handler has already been consumed — so the re-raise was a guaranteed
  no-op. Measured with a real `CTRL_C_EVENT` delivered to a child in its own
  process group: the first Ctrl-C wiped every secret and the process kept
  running, exiting only on a *second* one.

  That left it in the one state `WipeAllSecrets` does not support. The wipe
  deliberately leaves regions mapped so a late read returns zeros rather than
  faulting, a trade justified entirely by imminent termination — and reads
  still **succeed**. A surviving process therefore holds every key buffer
  readable and full of zeros, so an application treating the signal as "begin
  shutdown" can sign with an all-zero key or derive from zeros and be told it
  worked. Worse than either terminating or never wiping.

  secmem now exits with `0xC000013A` (`STATUS_CONTROL_C_EXIT`) — verified
  identical to the status Windows produces for an un-intercepted Ctrl-C, so no
  parent, batch file or CI step can tell a wrapped process from an unwrapped
  one. Unix is unchanged: the re-raise is a real `kill(2)` and already worked.

- **The emergency wipe could zero a different, live buffer without holding its
  lock.** The janitor keyed each registration by its mapping's base address.
  That is unique for a mapping's lifetime but not across lifetimes: free a
  region and the OS may hand the same base to the next allocation, which then
  registers under the identical key. `wipeInPlace` resolves a key, drops the
  janitor lock to wait on that region's lock, then resolves the key *again* — so
  a wipe blocked on a buffer that was destroyed during the wait could wake,
  resolve the key to the buffer now occupying that address, and zero it with
  `lockHeld=true`, i.e. with no lock on it at all. That races the new buffer's
  accessors and its `Seal`, which flips the pages to `PAGE_NOACCESS` mid-write.

  Reachable from the exact API combination the package documents as
  concurrency-safe: `WipeAllSecrets` running while one buffer is destroyed and
  another is allocated. Registrations are now identified by a counter, which
  cannot be reused, and the re-resolution additionally matches on the lock the
  caller actually holds — so the wipe is safe even if the key scheme changes
  again. Found by an external adversarial review; the reporter also flags it as
  a candidate mechanism for the unexplained one-off `windows/amd64` runtime
  corruption, since a stray write into re-handed address space lands in whatever
  the allocator gave that range next.

- **`memfd_secret` descriptors are now close-on-exec.** The fd was created with
  no flags and stayed inheritable across `ftruncate`, the guard reservation and
  the `MAP_FIXED` — so a `fork`+`exec` from any other goroutine in that window
  handed the child a live descriptor to the secret pages, making the strongest
  allocation tier the one that leaked across `exec`. The flag is `O_CLOEXEC`,
  not the `FD_CLOEXEC` the man page names: the kernel tests `flags & O_CLOEXEC`
  and `EINVAL`s anything else, so the wrong bit would have silently dropped
  every allocation to the weaker anon path. An `EINVAL` is retried bare with
  `fcntl(F_SETFD)` instead, so a kernel that disagrees still gets close-on-exec
  and never a tier downgrade.

- **`InstallTerminationWipe` no longer claims to terminate the process on
  Windows.** `os.Process.Signal` there supports only `os.Kill` and rejects both
  `os.Interrupt` and SIGTERM, so the re-raise was a guaranteed no-op whose error
  was discarded: the process ran on past Ctrl-C with every secret already
  zeroed, while the documentation said it exited. The failure is now logged and
  the platform limit is documented. The behaviour is deliberately not escalated
  to a forced `os.Exit`, because the installer promises never to take the exit
  away from a co-installed graceful shutdown.

- **`redact` credential rules missed the shape structured logs actually emit.**
  The Tier-1 patterns were `field[=:]\s*\S+`, which requires the separator to
  follow the key immediately — so `{"password": "hunter2"}` matched nothing at
  all and went to the sink in full. `\S+` also stops at the first space, so
  `password="hunter 2 correct horse"` was only partly masked, leaving the rest
  of the secret in the message. All five fields are now built by one helper that
  allows a quoted key and consumes a quoted value whole.

- **`redact`'s CWE-117 backstop passed the C1 controls it claimed to strip.**
  `stripNonPrintable` tested `r >= 32 && r != 127`, which lets every C1 code
  point (U+0080–U+009F) through while the doc comment said C0/C1. That includes
  U+009B, the single-character CSI, which a terminal decoding the stream as
  Latin-1/ISO-2022 acts on exactly as it would on the two-byte `ESC [` the ansi
  rule strips — so the backstop was bypassable by spelling the escape
  differently. Invalid UTF-8 bytes are now reported as redacted rather than
  silently becoming U+FFFD.

- **`redact`'s allowlist switched itself off when its label appeared twice.**
  `isAllowlisted` used `FindStringIndex`, which returns the EARLIEST match, and
  compared that match's end against the credential's start. A message mentioning
  the label anywhere earlier therefore failed the comparison and redacted a
  value the allowlist existed to exempt. All occurrences are now considered.

- **`redact.Handler` misfiled `WithAttrs` attributes into groups opened later.**
  It held them and re-added them to every record, so the inner handler emitted
  them at whatever nesting it had reached — meaning
  `log.With("req", id).WithGroup("db").Info(...)` produced
  `{"db":{"req":…}}` instead of `{"req":…,"db":{…}}`, violating the positional
  guarantee in `slog.Handler`'s contract. They are now handed to the inner
  handler at the point they are added, which is where that decision belongs.

- `WipeAllSecrets` no longer lets one borrowed buffer strand another's secret.
  The emergency wipe's second pass blocked on the deferred regions sequentially,
  in map-iteration order. Because `tryWipeInPlace` defers a region whose lock is
  held at the instant it looks — including momentarily — a buffer that was
  merely mid-`WithBytes` during the first pass could be serialized behind a
  genuinely stuck borrow and keep its plaintext for as long as that borrow ran.
  That is precisely the hostage situation the two-pass split exists to prevent,
  reintroduced by the second pass itself. Each deferred region is now waited on
  independently, so ordering cannot matter. Present since the two-pass wipe
  landed, and reachable on any `WipeAllSecrets` call — including from
  `InstallTerminationWipe` — whenever a second buffer was in use at the moment
  the wipe began.

- **`ArenaSlot.Release` no longer reports a spurious canary violation after an
  emergency wipe.** `WipeAllSecrets` zeroes the whole slab, canary strips
  included, and leaves it mapped; `Release` re-verified the strip without
  checking the arena's wiped flag, so every release after an emergency wipe
  returned `ErrCanaryViolation` — documented as a memory-safety bug report — for
  an overflow that never happened. It now skips the check (not the wipe) once the
  arena is wiped, as the janitor side already did.

- **`Seal` fails closed when the cipher rollback also fails (Windows).** On an
  mprotect failure Seal rolled the in-place cipher back; if that decrypt also
  failed it returned unsealed with the contents still ciphertext, so accessors
  handed out ciphertext as the secret and a retried Seal double-encrypted. It now
  stays sealed — the only state whose invariants still hold, and `Unseal`
  recovers it — and never runs the cipher over already-encrypted contents.

- **`EnsureMemlockLimit` no longer truncates the request or lowers a raised
  limit.** On windows/386 a request above 4 GiB wrapped through `uintptr` and was
  still reported as met; and two concurrent callers could each read the old limit
  and have the smaller one clobber the larger raise. The request is now bounds-
  checked against `uintptr`, the value returned is what was actually set, and the
  read-check-set is serialized.

- **The Linux frame-release step is no longer inert.** `madviseBeforeFree`
  advised `MADV_DONTNEED` on a still-mlocked region, which the kernel refuses
  with `EINVAL`, so the documented "release frames" step — and the
  unwiped-release fallback that leaned on it — did nothing. It now uses
  `MADV_DONTNEED_LOCKED`, accepted on both the anonymous and `memfd_secret`
  tiers; the per-tier guarantee is documented, and a failure on the
  unwiped-release path is surfaced rather than swallowed.

- **`scrubframe_arm64.s` carries the build constraint its amd64 counterpart
  has**, so `go vet` no longer fails on the linux/arm64 `runtimesecret`
  configuration, where the assembly was compiled without its Go declaration.

- **CPU feature detection checks the maximum CPUID leaf before querying leaf 7.**
  On a processor whose maximum basic leaf is below 7 the unguarded query returned
  another leaf's data, which could be read as a false `CLFLUSHOPT` flag and
  select a wipe path the CPU does not support.

- **The preempt window refuses to restore on the wrong OS thread.** If the
  scrubbed `fn` unbalanced `runtime.LockOSThread`, the goroutine could migrate
  mid-window and the restore would unmask signals on the wrong thread, leaving the
  original thread's `SIGURG`/`SIGPROF` blocked for the process lifetime — no
  async preemption, invisible to the profiler. The contract is now documented and
  a violation is detected rather than silently leaking.

- **The termination-wipe handler stays installed after a survived signal.** It was
  one-shot: with `InstallTerminationWipeNoExit` on Windows, or a co-installed
  handler on Unix, the process survives the first signal — but the wipe handler
  had already exited, so a secret created afterward would not be wiped on a second
  signal. It now re-arms when the process is left running. With
  `InstallTerminationWipeNoExit` on Windows that means a second Ctrl-C wipes
  again rather than ending the process on the default disposition —
  termination is the caller's, as NoExit promised.

- **Darwin gets a zero-on-release backstop for the teardown that never reaches
  the wipe.** A region released while still mlocked — the janitor's
  release-unwiped branch, or the kernel tearing down a process that died before
  the janitor ran — is now advised `MADV_ZERO_WIRED_PAGES` at allocation, so the
  kernel zeroes its frames on unwire. `freeSecretMem` no longer munlocks first:
  munmap unwires as part of deletion and is the only unwire that honours the
  advice (an explicit munlock clears the flag without zeroing). The limits are
  documented in the code from the XNU sources: full coverage for a writable
  region on macOS 26+, one page per entry on older kernels, and nothing for a
  sealed or read-only region on new kernels — no Darwin mechanism zeroes frames
  behind a mapping the process cannot write.

## [secmem-lint/v0.2.0] - 2026-09-07

The analyzer stopped certifying code it never examined: eight false-negative
classes closed, and receivers and parameters matched by object rather than by
name. Minor: analyzer behaviour changed.

### Fixed

- **`secmem-lint` no longer certifies code it never examined.** Eight
  false-negative classes, every one of which reported clean rather than
  reporting a limitation:

  - Assignment escapes matched only a bare identifier, so `s.field = b`,
    `m[k] = b`, `out[i] = b` and `*p = b` were all silently clean — stashing a
    borrowed slice in a struct field being the most natural way to leak one.
    Targets are now classified by shape, with a local struct or array value
    still correctly treated as staying inside the lease.
  - Logging **methods** could never match. The sink table is keyed by
    `import/path.Func`, so `sl.Info(b)`, `l.Printf("%s", b)` and
    `slog.Default().Warn(…, b)` all resolved their receiver to a variable or a
    call result rather than to a package name. Now matched by receiver type, so
    an unrelated `Info` method is still not swept in.
  - `append(dst, b[:n]...)` escaped unflagged, because only a bare identifier
    was matched where the rest of the file already used `refersToParam`.
  - `panic(b)` was not flagged, though the value lands in the runtime traceback
    and in any `recover()`.
  - Sink table omissions: `log.Panicln` (both its siblings were present),
    `log/slog.Log`, `log/slog.LogAttrs`, `fmt.Append`, `fmt.Appendf`,
    `fmt.Appendln`.
  - The reentrancy set omitted `SetByteAt`, which takes the **exclusive** lock
    and is therefore an unconditional self-deadlock, and the `rLock`
    inspectors `Len`, `MappedLen`, `IsSealed`, `IsDestroyed` — a nested read
    acquire deadlocks as soon as a writer queues between the two, because the
    lock is writer-preferring.

  All fifteen new fixture cases were verified to fail against the previous
  analyzer, so none of them is a vacuous assertion.

  The improved analyzer immediately caught a real instance in this repo's own
  shipped example: `ExampleScope` called `buf.Len()` from inside
  `buf.WithBytesErr`, taking the read lock a second time from within the borrow.
  Fixed to use `len(b)`, which the borrowed slice already carries and which
  needs no lock — the pattern the example should have been demonstrating.

- **`secmem-lint` matches receivers and parameters by object, not by name.**
  The reentrancy check silently did nothing when the buffer lived in a struct
  field or any non-identifier receiver, and the goroutine-capture check flagged
  shadowed variables that merely shared a parameter's name. Both were one
  defect — matching AST shape instead of `types.Object` — and are fixed together.

## [secmem-crypto/v0.3.2] - 2026-08-16

Retracts `secmem-crypto/v0.3.0`, and documents the module.

The `retract` directive is the supported way to mark a published version
unusable, and unlike a changelog note it reaches the toolchain — `go list -m
-retracted` and `go get` surface it to someone already on v0.3.0. A retraction
only ships in a *later* version, which is what this release is for. No source
change.

Adds `secmem-crypto/README.md`, which puts the reason this module reimplements
RFC 8032 signing above the fold: `crypto/ed25519`'s FIPS-140 path caches the
private key in a structure no wipe can reach, and panics outright on mmap'd
memory. "Rolled their own Ed25519" deserves scrutiny, so the justification
should not be buried in a per-file comment.

## [secmem-crypto/v0.3.1] - 2026-08-16

Dependency-only release: requires `secmem` v0.3.0, so code importing only this
module resolves the v0.3.0 core.

Supersedes `secmem-crypto/v0.3.0`, which was tagged from a commit predating the
`go.mod` change and therefore still requires `secmem` v0.2.0. That tag is left
published: `proxy.golang.org` and `sum.golang.org` are append-only, so
re-pointing it would only make this repository disagree with them.

## [0.3.0] - 2026-08-16

The result of the library's first adversarial audit. Every finding below was
reached from the source rather than reported in the field, so nothing here is
known to have bitten anyone — but two of them are the kind that would never have
announced themselves: a compiler barrier that was not one, and an emergency wipe
that leaked the mappings it wiped.

`ErrWiped`, `Capabilities.FrameScrub`, and `Capabilities.AsyncPreemptSuppressed`
are the only API additions and nothing was removed, so the change is backward
compatible (confirmed by `gorelease`). Behavior changes that the type surface
does not show are listed under **Changed** — read that section before upgrading.

### Fixed

- **The portable wipe's compiler barrier was not a barrier.** `secureWipe` on
  every architecture without wipe assembly — everything except amd64 and arm64
  — zeroed via `subtle.ConstantTimeSelect(1, 0, b[i])`. With a constant selector
  that whole expression folds to a constant `0` at compile time, leaving exactly
  the plain zeroing loop over never-read-again memory that it was written to
  protect from dead-store elimination. Go's compiler does not currently remove
  that loop, so this is a latent hole rather than a known leak, but "does not
  currently" is not a guarantee and the package's entire promise rests on the
  zeros reaching memory. The wipe now takes its zero byte from a package-level
  atomic (not a compile-time constant), reads every byte back into an
  accumulator, and publishes the accumulator to a second atomic, so the stores
  are provably observed. Verified in the GOARCH=386 disassembly: both loops and
  both atomics survive.
- **`WipeAllSecrets` no longer leaks the mappings it wipes.** It deliberately
  leaves regions mapped so a late read returns zeros instead of faulting on
  freed memory — but nothing ever completed the unmap, so the address space and
  the locked pages were held until process exit. Wiped regions are now retained
  separately, and a later explicit `Destroy` — or the GC cleanup once the
  wrapper is unreachable — finishes the reclaim. That is safe where the
  emergency path is not: both run with no accessor in flight.
- **One slow borrow no longer holds the whole emergency wipe hostage.** Wiping a
  region takes its exclusive lock, so a buffer parked inside a `WithBytes`
  callback cannot be wiped until that callback returns — correct, since zeroing
  memory a callback is reading is a data race. But the single blocking pass
  meant one slow borrow delayed every *other* secret in the process, in registry
  map order. The wipe now runs a non-blocking pass first and blocks only on what
  is left, so a stuck borrow delays only its own buffer.
- **A `Destroy` racing the emergency wipe no longer strands the mapping.** The
  blocking wipe pass removed a region from the registry *before* taking its
  lock, leaving a window in which the key was in neither the live set nor the
  wiped set. A `Destroy` already queued on that same lock reached the janitor
  inside that window, found nothing to free, reported success, and never
  unmapped; the retain that landed afterwards then filed the region where
  nothing collects it. The GC-cleanup path was worse, since its cleanup is
  stopped and never runs again. The lock is now held across the whole take /
  wipe / retain sequence. Reached by the exact API pair `WipeAllSecrets`
  documents as safe to use concurrently.
- **`memfd_secret` mappings now apply `MADV_DONTFORK`, and report whether it
  took.** The L4 mapping is `MAP_SHARED`, so a forked child did not inherit a
  copy-on-write snapshot of the secret pages — it shared the live ones. `noFork`
  was reported `false` without anything having been attempted. It is now
  attempted and the outcome reported honestly per allocation.
- **windows/386 did not compile.** The WER dump-exclusion size bound was written
  `int(^uint32(0))`, whose constant overflows `int` on a 32-bit word. Widened to
  `uint64`, and the cross-compile matrix gained the windows/386 row that would
  have caught it — nothing else in it is both Windows and 32-bit.

### Added

- `ErrWiped` — returned by every mutating method after `WipeAllSecrets` has
  emergency-wiped the object, and by `SecureArena.Acquire`. Previously those
  calls succeeded, which let a process that kept running write a *fresh* secret
  into a region the emergency wipe had already reported as handled. Reads still
  work and return the zeros. It wraps `ErrDestroyed`, so existing
  `errors.Is(err, ErrDestroyed)` checks keep working unchanged; test for
  `ErrWiped` only to tell "the process emergency-wiped this" apart from "the
  owner destroyed this".
- **Asynchronous-preemption suppression inside `Scrub` windows (Linux).** Go's
  non-cooperative preemption is signal-delivered, and `runtime.asyncPreempt`
  saves the entire user register file — general purpose and vector — onto the
  goroutine stack at an arbitrary instruction boundary. Land one inside a cipher
  round and a copy of live key material is written to the stack at an offset
  nothing chose and nothing tracks. `Scrub` now blocks SIGURG for the duration
  of its window, so that spill cannot happen. Cooperative preemption is
  untouched, so the collector still reaches the goroutine through ordinary calls
  — but a window whose callback contains an unbounded loop with no function
  calls offers no cooperative preemption point either and will stall `suspendG`;
  keep callbacks short and call-bearing, which the borrowing contract already
  asks for. Unavailable on Windows (preemption there rewrites thread context
  rather than delivering a signal, and nothing in userspace can mask that) and
  on Darwin (no `PthreadSigmask` in `x/sys/unix`).
- **arm64 scrub-frame assembly.** `Scrub`'s stack-band burn was amd64-only and
  silently did nothing elsewhere; arm64 now has a real implementation.
- `Capabilities.FrameScrub` and `Capabilities.AsyncPreemptSuppressed` — report
  whether the two mechanisms above are real on the running platform rather than
  leaving callers to infer it. Both feed `Warnings()`.
- **THREAT-MODEL.md gains a stack-residue section** enumerating what `Scrub`
  reaches, what it does not, and — stated separately — which of the gaps are
  constraints of the Go runtime or the OS rather than defects. KERNELS.md and
  TESTING.md record the verified kernels and the contention measurements behind
  the lock rework.

### Changed

- **`SecureArena` per-slot bookkeeping dropped from 90 to 16 bytes** — measured
  at 4096 × 32-byte slots, where the Go-heap index went from 1.88× the locked
  slab it describes to 0.34×. For a type whose stated purpose is hundreds of
  short-lived per-session keys, the metadata previously cost nearly twice the
  secrets. Three changes got there: `slotMeta` now carries one `atomic.Uint64`
  generation that encodes liveness in its low bit (even = free, odd = live)
  instead of a separate flag padded to a cache line; the free list is an
  intrusive `int32` link inside `slotMeta` rather than a separate `[]int`; and
  the canary zones are a fixed-size descriptor regenerated on demand rather than
  a materialized `[][2]int` costing 16 bytes per slot.
- **The arena borrow path is now lock-free.** Slot liveness is one atomic load
  and compare against the handle's generation, with no mutex on the read side.
- **`SecureArena.Acquire` and `LiveCount` are O(1)**, not a scan over every
  slot. A consequence worth knowing: after any `Release`, `Acquire` hands out
  the most recently freed slot rather than the lowest free index. A fresh arena
  still hands out 0, 1, 2, … Nothing documented the old order, but code that
  depended on it will observe the change.
- **`NewArena` now rejects `count > math.MaxInt32`** with an error, rather than
  overflowing the intrusive free link quietly.
- **The buffer read-write lock has an atomic read fast path.** The read side
  sits under every `SecureBuffer` access and every `ArenaSlot` borrow, and it
  previously took a mutex in both directions. Measured, that was ~85% of the
  cost of an arena borrow at 16 cores, and aggregate throughput *fell* as cores
  were added — goroutines borrowing entirely disjoint secrets were serializing
  on it. Readers now enroll with a single atomic add and take no mutex unless a
  writer is involved. Writers stay on the mutex-and-cond slow path, so every
  blocking state remains durably blocked under `testing/synctest`. Writer
  preference is unchanged.
- **`WipeAllSecrets` documents that it can block**, which it always could. A
  borrowing callback that never returns blocks it forever; the alternative would
  be zeroing memory a callback is actively reading. The two-pass wipe contains
  the cost to the offending buffer. If your shutdown path must be bounded, run
  it in its own goroutine and exit on a timer — the first pass will have done
  its work regardless.
- **`EnsureMemlockLimit` documents that it disarms an implicit guard.** A
  bounded `RLIMIT_MEMLOCK` is incidentally what stops an oversized `NewArena`
  from killing the process: `NewArena` requests its locked slab before its
  Go-heap slot index precisely because a refused slab returns an error while a
  refused heap allocation is `runtime.throw`, which no `defer` and no `recover`
  survives. Raising the budget raises that ceiling with it; raising it to
  unlimited removes it. If you raise it and then size arenas from something
  outside your control, bound the count yourself.
- **The `RLIMIT_MEMLOCK` guidance is now measured rather than folklore.** The
  ceiling is `RLIMIT_MEMLOCK / pagesize` buffers exactly, and current
  systemd-based distributions default it to 8 MiB — 2048 buffers at 4 KiB
  pages, measured on stock Ubuntu 26.04/amd64 and Armbian/arm64 — not the
  historical 64 KiB kernel default that allowed about a dozen. Read the runtime
  limit rather than designing against either number.

## [secmem-crypto/v0.2.0] - 2026-07-19

Dependency-only release. `secmem-crypto` now requires `secmem` v0.2.0, so code
that imports only this module picks up the read-only crash fix below — v0.1.0
of this module pins `secmem` v0.1.0 and would otherwise keep resolving the
faulting core.

No `secmem-crypto` source change: the only additions since
`secmem-crypto/v0.1.0` are the `FuzzSignerLifecycle` state-machine fuzzer and
its seed corpus, both test-only. It is a **minor** bump rather than a patch
because this module's exported API hands back `*secmem.SecureBuffer` values,
so raising its `secmem` floor to v0.2.0 raises the minimum for every consumer
too — a dependency-graph change they should opt into deliberately
(`gorelease` classifies it the same way).

## [0.2.0] - 2026-07-19

A bug-fix release for the core `secmem` module, and the reason to upgrade
promptly: v0.1.0 could **crash the process** on a documented API sequence.
`ErrReadOnly` is the only API addition, so the change is backward compatible
(confirmed by `gorelease`).

### Fixed

- **Read-only buffers and arenas no longer fault the process on a mutating
  call.** `ReadOnly()` sets the region to `PROT_READ`, but the mutating methods
  did not check for it, so a `SecureBuffer.CopyIn`, `SetByteAt`, `Truncate`, or
  `ReadFrom` — or an `ArenaSlot.Release`, which wipes the slot — issued after
  `ReadOnly()` wrote to the read-only page and crashed the process with SIGSEGV.
  They now return the new `ErrReadOnly` at the API boundary instead, honoring
  the "misuse returns an error, never crashes" contract. `Release` refuses
  without wiping — the slot stays acquired, and `ReadWrite` then `Release`, or
  `Destroy`, completes the wipe. Surfaced by the new lifecycle fuzzers.
- **Read-only state now survives a `Seal`/`Unseal` cycle on every platform.**
  The Windows seal cipher (`CryptProtectMemory`) encrypts in place, so `Seal()`
  on a read-only `SecureBuffer` failed there while succeeding on Linux. `Seal`
  now lifts the read-only protection for the encrypt and `Unseal` restores it,
  so a read-only buffer sealed for dormancy is still read-only when it wakes —
  the physical page protection always matches the flag.

### Added

- `ErrReadOnly` — the sentinel returned by the mutating methods and
  `ArenaSlot.Release` when the buffer or arena is in the read-only
  (`PROT_READ`) state. Call `ReadWrite` before mutating.
- `FuzzBufferLifecycle` and `FuzzArenaLifecycle` — state-machine fuzzers that
  drive a buffer or arena through arbitrary operation sequences against a
  model, asserting that misuse always returns the right sentinel and never
  panics or faults. They found the read-only faults fixed above.
- `DESIGN.md` — why the layered protections are arranged as they are — and
  `PITFALLS.md` — the common secure-memory mistakes and their correct forms.

## [secmem-lint/v0.1.0] - 2026-07-14

First tagged release of the `secmem-lint` module — a `go/analysis` analyzer
(and `cmd/secmem-lint` vet tool) enforcing secmem's borrowing-closure
discipline at compile time: the slice borrowed from `WithBytes`/`WithBytesErr`
(and `WithScalar`/`WithSeed`/`WithDER` in `secmem-crypto`) must not escape the
closure. Default checks cover `string()` conversion, append-spread, copy /
channel / goroutine / assign-to-outer escape, and dangerous stdlib sinks;
`-strict` adds the same-buffer-reentrancy (R1) and secret-in-plain-string (N1)
checks. Its own module (`golang.org/x/tools` only), so it adds nothing to
either library module's dependency graph.

## [secmem-crypto/v0.1.0] - 2026-07-16

First tagged release of the `secmem-crypto` module. Depends on `secmem`
v0.1.0 — the in-repo `replace` development bridge is gone as of this
release, so the module is consumable outside this checkout.

### Added

- `Ed25519Signer` — a `crypto.Signer`/`crypto.MessageSigner` whose Ed25519 seed
  lives in a `SecureBuffer` for its entire lifetime, with in-place RFC 8032
  signing that bypasses `crypto/ed25519`'s FIPS cache (which panics on
  mmap'd memory). Pure Ed25519 only; Ed25519ph and Ed25519ctx requests are
  refused rather than silently mis-signed. `WithSeed` provides the
  deliberate, documented egress point for generate-then-persist flows.
- `HKDFInto` / `HKDFSHA256Into` — RFC 5869 HKDF deriving directly into a
  `SecureBuffer`, with the full salt/info parameter surface (verified
  against RFC 5869 test cases 1–3) and hash agility.
- `HMACInto` / `HMACSHA256Into` — a raw keyed-HMAC PRF deriving directly into
  a `SecureBuffer`, for domain-separated subkey derivation from an
  already-uniform secret. Distinct from `HKDFInto`: HKDF's Extract step also
  computes an HMAC, but with `secret` and the key argument swapped for its
  own purpose, so the two are not interchangeable — verified against a
  published RFC 4231 test vector and hash-agile beyond SHA-256.
- `GenerateDicewarePassphrase` — a diceware-style passphrase drawn from the
  EFF long wordlist (7776 words, CC BY 3.0 — see `secmem-crypto/NOTICE`)
  via `crypto/rand`, assembled directly inside the returned `SecureBuffer`'s
  own memory with no intermediate heap string at any point. Word selection
  and assembly run inside a `ScrubErr`-guarded region, since which words are
  chosen and in what order is the passphrase, even though each word's text
  is public.
- `Argon2IDKeyInto` / `Argon2DeriveInto` — Argon2id deriving directly into a
  `SecureBuffer`; explicit cost parameters are validated (error, never
  panic), and the defaults follow RFC 9106 §4's second recommended option,
  frozen permanently.
- `WipeEd25519Scalar` — hardened wipe for `edwards25519.Scalar` values,
  whose unexported fields `SecureWipe` cannot reach.
- `OpenInto` / `SealFrom` — AEAD decryption directly into a `SecureBuffer`,
  and encryption straight from one, so an AEAD plaintext never lands on the
  heap as an intermediate. A tampered ciphertext leaves the buffer zeroed;
  the in-place decrypt is measured at zero allocations.
- `X25519Key` — X25519 Diffie-Hellman with the private scalar in a
  `SecureBuffer`; `PublicKey`/`SharedSecret` (returned hardened, low-order
  points rejected)/`WithScalar`/`ConstantTimeEqual`. Verified against
  RFC 7748 vectors.
- `MLKEM768Key` — post-quantum ML-KEM-768 (FIPS 203) decapsulation-key
  custody: 64-byte seed in a `SecureBuffer`, expanded per operation;
  `EncapsulationKeyBytes`/`Decapsulate`/`WithSeed`. `Encapsulate`
  hardens the sender side too, delivering the encapsulating peer's shared
  secret into a `SecureBuffer` instead of the plain heap.
- Fuzz targets (sign-vs-stdlib, HKDF, Argon2 params, AEAD round-trip,
  X25519-vs-stdlib) and benchmarks with allocation reporting across the
  sign, AEAD, DH, and KEM paths.
- `ECDSASigner` — a `crypto.Signer` for P-224/P-256/P-384/P-521 with the raw
  scalar in a `SecureBuffer` between operations. ECDSA is deliberately NOT
  reimplemented (per-signature nonce arithmetic is where implementations
  leak keys); each Sign transiently materializes a stdlib key via
  `ecdsa.ParseRawPrivateKey`, signs, and zeroes the transient's limbs, with
  the residue that can't be reached documented honestly. Deterministic
  RFC 6979 mode (nil `random`) verified against the RFC's test vectors and
  differentially fuzzed byte-identical against stdlib; generation uses
  candidate testing so the scalar is born inside the `SecureBuffer`.
- `RSASigner` — a `crypto.Signer` with the RSA key held as PKCS#1 or PKCS#8
  DER (auto-detected) in a `SecureBuffer`, transiently parsed per operation
  under the same wipe discipline, PKCS#1 v1.5 and PSS via stdlib.
  Signing-only by design (no `crypto.Decrypter`); the per-operation heap
  exposure of the full key is documented rather than downplayed.
- `AsSSH` — adapts any `crypto.Signer` to `golang.org/x/crypto/ssh`. For RSA
  keys the returned signer makes legacy `ssh-rsa` (SHA-1) unreachable on
  every path — negotiation offers only `rsa-sha2-512`/`rsa-sha2-256`,
  explicit requests for `ssh-rsa` error, and plain `Sign` (which x/crypto's
  own restricted signer still routes to SHA-1) is overridden to rsa-sha2-512.
- Runnable examples showing the two most common adoption points for a
  `crypto.Signer`: `ExampleECDSASigner_tlsCertificate` (self-signing an
  `x509.Certificate` and assembling a `tls.Certificate` — what
  `tls.Config.Certificates` expects) and `ExampleAsSSH_hostKey` (wiring an
  adapted signer into `ssh.ServerConfig.AddHostKey`).
- ML-KEM-768 accumulated known-answer test pinning the wrapper's keygen and
  decapsulation byte-for-byte to the standard library's FIPS 203
  implementation (upgrading it from round-trip-only), a published AES-256-GCM
  vector threaded through `SealFrom`/`OpenInto`, a `testing.AllocsPerRun` gate
  enforcing `OpenInto`'s zero-heap-escape, and a proof that `Sign` wipes its
  live transient key (not just the wipe helpers in isolation).

## [0.1.0] - 2026-07-16

First tagged release of the core `secmem` module.

### Added

- `SecureBuffer` — off-heap, page-locked secret storage with borrowing-closure
  access (`WithBytes`/`WithBytesErr`), copy-out/in, sealing, read-only
  protection, and deterministic wipe on `Destroy`.
- `WipeAllSecrets` and `InstallTerminationWipe` — opt-in emergency wiping. The
  library installs **no** signal handler by default (importing it never touches
  process-global signal state); a consumer either calls `WipeAllSecrets` from
  its own shutdown handler or opts into `InstallTerminationWipe`, a cooperative
  termination-signal handler that deregisters only its own channel and never
  resets or ignores other handlers.
- `SecureArena` — a single locked slab of fixed-size slots for many small,
  short-lived secrets at O(1) OS overhead, with ABA-guarded acquire/release.
- `Secret` — a leak-safe value type that renders as `[REDACTED]` through
  `fmt`, `encoding/json`, and `log/slog`.
- `Capabilities` and `Probe` — honest, per-allocation and per-platform
  reporting of which protections are actually in force, with `Warnings()` and a
  one-line `String()`.
- Guard pages and an overflow canary bracketing every allocation; a linear
  over/under-flow faults or is caught on destroy. On Linux this includes the
  `memfd_secret` `MAP_FIXED`-into-a-reservation construction.
- `Scrub` / `ScrubErr` — register, stack, and heap residue erasure via
  `runtime/secret` where available (`GOEXPERIMENT=runtimesecret`), with a
  best-effort stack-frame wipe elsewhere.
- Fail-closed policy on platforms with no lockable off-heap memory:
  constructors return `ErrNoSecureMemory` unless `WithInsecureFallback()` is
  passed.
- Process-hardening helpers: `HardenProcess` (dumpable=0 and no-new-privs on
  Linux; Arbitrary Code Guard and strict handle checks on Windows),
  `DisableCoreDumps`, and `EnsureMemlockLimit`.
- Platform dump/copy hardening applied by the allocator: `MADV_DONTDUMP` /
  `MADV_DONTFORK` / `MADV_NOHUGEPAGE` / `MADV_UNMERGEABLE` on Linux; WER dump
  exclusion and a kernel-keyed sealed-state cipher (`CryptProtectMemory`) on
  Windows.
- `secmem/redact` subpackage — a configurable `Sanitizer` and an `slog.Handler`
  wrapper for boundary-level log scrubbing (credential masking and CWE-117
  injection neutralization). Standard library only.
- `KERNELS.md` — a log of the Linux kernels the suite has been executed on, with
  the guard-fault, `memfd_secret`-isolation, and canary proofs recorded per row.
  Now includes real **arm64** (Ampere Altra) and a spread of amd64 kernels
  (5.10 → 7.x) run on disposable cloud hardware.
- `ENVIRONMENTS.md` — how secmem behaves across root / non-root / rootless and
  constrained `RLIMIT_MEMLOCK`, and why `memfd_secret` availability is a kernel
  `CONFIG_SECRETMEM` property rather than a version guarantee.
- `TESTING.md` — the verification companion to the guarantee matrix: every
  security claim mapped to the test that proves it, or the stated reason it
  cannot be (the fused wipe+munmap, the structural constant-time argument).
- CI now runs the `GOEXPERIMENT=runtimesecret` variant (so the
  register/stack/heap erasure integration tests actually execute) and executes
  the suite on 32-bit x86 rather than only compiling it; a
  `testing.AllocsPerRun` gate enforces no-heap-escape on the borrow/copy/
  compare paths.

### Fixed

- `SecureBuffer`, `SecureArena`, and `ArenaSlot` now redact themselves under
  every formatting and logging path (`fmt`'s `%v`/`%+v`/`%s`/`%x`, `Println`,
  error-wrapping, `log/slog`) — matching `Secret`'s existing behavior. Without
  this, `fmt`'s default struct printer reflected into the guarded region and
  crashed the process with an unrecoverable hardware fault rather than
  printing anything; the crash, not a plaintext leak, was the actual failure
  mode on every path tested. Found in a pre-release audit; regression tests
  cover all three types, both the pointer and (where a value copy is not
  itself a `go vet` copylocks violation) a dereferenced value.

[Unreleased]: https://github.com/deadpoets/secmem/compare/v0.3.0...HEAD
[secmem-crypto/v0.3.2]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.2
[secmem-crypto/v0.3.1]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.1
[secmem-crypto/v0.3.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.3.0
[0.3.0]: https://github.com/deadpoets/secmem/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/deadpoets/secmem/compare/v0.1.0...v0.2.0
[secmem-crypto/v0.2.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.2.0
[secmem-lint/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-lint%2Fv0.1.0
[secmem-crypto/v0.1.0]: https://github.com/deadpoets/secmem/releases/tag/secmem-crypto%2Fv0.1.0
[0.1.0]: https://github.com/deadpoets/secmem/releases/tag/v0.1.0
