# Changelog

scuttle is v0: the wire format is not stable. Every entry that changes what is
stored, or how a stored record is read, says so under **Format**.

## v0.1.0 — first public release (unreleased)

Write-only payload encryption: hybrid ML-KEM-768 + X25519 leaf wrapping,
AES-256-GCM field encryption with HKDF-derived keys, capture-key rotation,
optional row authentication (`Envelope.AuthKey`), and optional uncompressed
fields (`Envelope.DisableCompression`).

Two internal, AI-assisted reviews ran before this release: a first pass, then
three separate AI reviewers (construction, implementation, public claims), each
working from a frozen snapshot without the others' notes. **Neither is an
independent audit by human cryptographers**; the code has not had one. Every
finding below is fixed and pinned by a test that failed before the fix.

### Security — first internal review

- **Row authentication against storage writers.** `Envelope.AuthKey` (32
  secret bytes shared by writers and readers, never stored) derives the field
  key with `HKDF(salt = AuthKey)` under a separate domain separator, so someone
  who can write to the database cannot plant a row that opens as another
  tenant's. Without it they can, and the README says so.
- **Seal enforces the plaintext cap**, returning `ErrPlaintextTooLarge`,
  instead of writing a row `Open` would refuse forever. `MaxPlaintext` above
  `MaxPlaintextCeiling` (16 MiB) is `ErrInvalidConfig`.
- **Error classification.** A row with no sealed leaf is `ErrUndecryptable`
  (it said "retry", forever). A leaf wrapping anything but a 32-byte key is
  `ErrUndecryptable`. `Open` with a wrong-length key returns a declared error.
  A cancelled context is `ErrKeyUnavailable` wrapping the context error.
- **Rotation.** A row with no generation stamp is tried against every
  generation, active first, so rows from before the stamp survive a rotation.

### Security — second internal review

- **The documented AuthKey cutover re-opened forgery.** It said to choose the
  envelope per row from `Binding.SchemaVersion`, a column the forger writes.
  The cutover is now: give writers the key, re-seal existing rows once with the
  new `Reseal`, then read with the authenticated envelope only. A test pins
  that the old advice accepts forgeries.
- **Decompression was bounded by 16 MiB, not by the cap.** A row under 2 KB
  made a reader with a 1 MiB cap allocate 16 MiB, and a frame without a
  declared size about 90 MiB. Decoders are now bounded per cap, and the tests
  measure allocation instead of only checking for an error.
- **Compression is a length oracle within one field** (CRIME, when a secret
  sits beside attacker-influenced text). Documented, and
  `Envelope.DisableCompression` stores such fields uncompressed.
- **All-zero keys are refused** — the exact shape of the historical bug in
  ATTACK.md claim 1: `Seal`, `Open` and `OpenLeaf` reject an all-zero leaf key.
- **An empty seed no longer makes a random keyring.** `NewLocalKeyring` with
  an empty seed is `ErrInvalidConfig` (an unset variable used to start a
  reader that could open nothing); `NewEphemeralKeyring` asks for one by name.
- **A public key that cannot be sealed to** (e.g. a low-order X25519 point) is
  refused when it is loaded, not on every later write.
- **Denial of service by hostile rows:** leaf ids are capped at 256 bytes; row
  values in error messages are truncated; a full leaf cache sheds a quarter
  instead of emptying; `RequireGenerationStamp` turns off the try-every-
  generation fallback once no unstamped rows remain.
- **Configuration mistakes are `ErrInvalidConfig` everywhere**: keyring and
  sealer constructors, negative `MaxPlaintext`, an empty field name, a
  wrong-length or all-zero key.
- **Documented non-properties:** columns outside `Binding` are not
  authenticated; `RequestID` must be unique per stored record; a compromised
  writer can write rows under past bindings until the `AuthKey` is rotated.

### Security — verification of the second review

A fresh AI reviewer re-tested every fix above against the fixed code:

- **Frame floods.** The per-cap decoder bounded the result, not the copying:
  zstd reallocates the output for every frame that declares a size, so a
  22 KB row of many small frames cost 2 GB under a 1 MiB cap. Decoding now
  goes into a fixed buffer that cannot grow (at most about 2.8× the cap in
  every tested attack), and a blob longer than the cap allows is refused
  before it is decrypted.
- **The cutover docs** now say the forgery window lasts until the re-sealing
  migration finishes, and that readers must not fall back between envelopes.
- Sealed-leaf blobs must be exactly 1168 bytes; a nil `KeyringOption` no
  longer panics; decoder concurrency is capped at 4, bounding memory kept
  between calls.

### Added

- `Reseal`, `NewEphemeralKeyring`, `RequireGenerationStamp`,
  `Envelope.DisableCompression`, `MaxLeafIDLength`.
- `ErrPlaintextTooLarge`, `ErrInvalidConfig`, `AuthKeySize`,
  `MaxPlaintextCeiling`.
- `GenerateCaptureSeed`, `GenerateAuthKey`, `ParseCaptureSeed`,
  `ParsePublicKey`, `ParseAuthKey`, and `cmd/scuttle-keygen`.
- `SPEC.md`, with known-answer vectors in `testdata/vectors.json` covering both
  modes, negative and non-ASCII bindings, an unstamped row and an
  uncompressed row.
- A runnable `Example`, and a test that compiles the README's usage snippets.

### Changed

- All cryptography comes from the Go standard library (`crypto/hpke`,
  `crypto/hkdf`, `crypto/aes`, `crypto/cipher`); the only dependency is
  `klauspost/compress`. Moving HKDF off `golang.org/x/crypto` changed no output
  (pinned by the vectors).
- Encoders and decoders run concurrently; every `Seal` and `Open` in a process
  used to run one at a time, so one slow row stalled all of them.
- `NewLocalKeyring(nil)` is an error; use `NewEphemeralKeyring`.

### CI

- The fuzz jobs never ran: `go test -fuzz` refuses more than one package, and
  they were given `./...`. They now target the root package, and a test checks
  the command form.
- Tests run on the `go.mod` minimum and on the latest 1.26 patch release;
  `govulncheck` and fuzzing on the latest. Actions are pinned to commits and
  kept current by Dependabot.

### Format

- Two modes, both pinned by the vectors: unauthenticated (`orca/rlog/v1`) and
  authenticated (`orca/rlog/v1/auth`). A reader with an `AuthKey` does not open
  unauthenticated rows, by design.
- Uncompressed fields are ordinary zstd frames of raw blocks (SPEC.md §5), so
  every reader opens them.
