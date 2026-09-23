# Changelog

scuttle is v0: the wire format is not stable. Every entry that changes what is
stored, or how a stored record is read, says so under **Format**.

## v0 — first public release

Write-only payload encryption: hybrid ML-KEM-768 + X25519 leaf wrapping,
AES-256-GCM field encryption with HKDF-derived keys, capture-key rotation,
optional row authentication (`Envelope.AuthKey`).

### Hardened before release

A pre-release audit found the issues below; each is fixed and pinned by a test.

- **Row authentication against storage writers.** New `Envelope.AuthKey`
  (32 secret bytes shared by writers and readers, never stored). With it, the
  field key is derived with `HKDF(salt = AuthKey)` under a separate domain
  separator, so someone who can write to the database can no longer plant a row
  that opens as another tenant's. Without it they still can, and the README now
  says so in the threat model. See README → *Authenticating rows*.
- **Seal enforces the plaintext cap.** `Seal` used to accept bodies that `Open`
  would refuse, so an over-cap write succeeded and the row was unreadable
  forever. It now returns `ErrPlaintextTooLarge`. `MaxPlaintext` above
  `MaxPlaintextCeiling` (16 MiB) is now `ErrInvalidConfig`; it used to be
  silently lowered on read.
- **Error classification.**
  - A sealed leaf with no blob or no leaf id is `ErrUndecryptable`, not
    `ErrKeyUnavailable` — it will never become readable, and "retry" looped.
  - A leaf blob that wraps anything other than 32 bytes is `ErrUndecryptable`
    instead of being returned as a key.
  - `Open` with a wrong-length key returns `ErrUndecryptable` instead of an
    undeclared error.
  - A cancelled context from `OpenLeaf` is `ErrKeyUnavailable` wrapping the
    context error.
- **Rotation.** A row with no generation stamp is tried against every
  generation, active first, instead of only the active one — so pre-stamp rows
  survive a rotation.

### Added

- `ErrPlaintextTooLarge`, `ErrInvalidConfig`, `AuthKeySize`,
  `MaxPlaintextCeiling`.
- `GenerateCaptureSeed`, `GenerateAuthKey`, `ParseCaptureSeed`,
  `ParsePublicKey`, `ParseAuthKey`.
- `cmd/scuttle-keygen`, which prints a fresh key set.
- `SPEC.md`, with known-answer vectors in `testdata/vectors.json`.
- A runnable `Example` in `example_test.go`.
- Fuzz target `FuzzWhatSealAcceptsOpens`.
- CI: `govulncheck`; every action pinned to a commit; `FuzzLeafCacheNeverCrossesRows`
  and the new target added to both fuzz jobs, with a test that fails if CI
  stops running any target.

### Format

- Two modes, both pinned by `testdata/vectors.json`: unauthenticated
  (`orca/rlog/v1`) and authenticated (`orca/rlog/v1/auth`). A reader with an
  `AuthKey` does not open unauthenticated rows, by design.
