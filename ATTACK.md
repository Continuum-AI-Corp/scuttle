# Break this

An invitation, and a list of the claims worth aiming at. If you get any of
these, we want to know — see [SECURITY.md](SECURITY.md).

This is **v0 and not independently audited**. We are not claiming it is
unbreakable; we are writing down precisely what we think it does so that being
wrong is *checkable* rather than a matter of opinion.

## Start here

```bash
git clone https://github.com/Continuum-AI-Corp/scuttle && cd scuttle
go test ./...                                    # ~2s
go test -run=Fuzz -fuzz=FuzzRoundTripBindsEveryField -fuzztime=10m
```

Nine fuzz targets in `fuzz_test.go`, each asserting an invariant rather than
merely "does not panic":

| Target | Invariant it tries to break |
| --- | --- |
| `FuzzRoundTripBindsEveryField` | A blob does not open under any different binding or field |
| `FuzzOpenRejectsGarbage` | Hostile bytes never yield plaintext, and every rejection is one of the two declared errors |
| `FuzzTamperIsAlwaysDetected` | No single-bit change anywhere in a blob survives |
| `FuzzOpenLeafRejectsGarbage` | A hostile `SealedLeaf.Blob` cannot forge a leaf key |
| `FuzzDecompressionIsBounded` | A compression bomb is refused *before* allocation, not measured after |
| `FuzzRotationNeverServesTheWrongGeneration` | Across several capture-key generations, a leaf opens to the key that sealed it — never another's, never a cached entry for a different blob |
| `FuzzMultiKeyringRejectsHostileSeedSets` | A keyring never comes up holding a seed set it should have refused |
| `FuzzLeafCacheNeverCrossesRows` | With both rows already cached, no recombination of (generation, leaf id, blob) is answered with another row's key |
| `FuzzWhatSealAcceptsOpens` | Anything `Seal` returns without error, `Open` under the same `Envelope` returns unchanged — a successful write is never an unreadable row |

`TestCI_RunsEveryFuzzTargetInBothJobs` derives this list from the source and
fails if CI stops running any of them, and `TestAttackMd_ListsEveryFuzzTargetAndCountsThemRight`
fails if this table does.

**What we have actually run**, so you know where the frontier is: each target
for a minute or two, on the order of tens of millions of executions in total.
That is a smoke test, not a campaign.

**It has already found two, and the same six lines produced both.** The
opened-key cache decides when to skip an HPKE open, so its key has to name
every input that determines the answer: the capture-key *generation*, the
*leaf id* (which `leafInfo` binds into the open), and the *blob*. Three
spellings shipped, each covering a strict subset:

| Cache key | What it crossed | Found by |
| --- | --- | --- |
| leaf id | generations | review |
| (generation, leaf id) | blobs — two leaves minted with the same id hold different random keys | `FuzzRotationNeverServesTheWrongGeneration`, on its first seed |
| blob | leaf ids — a row presenting a valid blob under another id was served from cache with the binding never checked | review |

The third was the *fix* for the second, written the same day, and it was
caught by a review pass rather than by the fuzzer, because no target primed
the cache before recombining a row. `FuzzLeafCacheNeverCrossesRows` now does,
and it fails on its seed corpus against any of the three. The key is a
length-prefixed hash over all three inputs.

Worth noticing what that sequence says about the frontier: the second bug lived
in code written three days earlier and reviewed three times, and the third was
introduced while fixing the second. Nobody has run these for hours, on a
cluster, or with a dictionary. The interesting inputs are almost certainly
still out there.

## The claims

Ordered by what it costs us if you are right.

### 1. A stolen database is worth nothing without the capture private key

The severe one. Everything else is a detail.

Sealed rows carry: ciphertext, a wrapped leaf key, and plaintext metadata. If
you can recover any payload plaintext from a database dump — no private key, no
access to a live process — that is the whole design failing.

Worth noting that **this exact class of bug has already happened here once**,
found in review and fixed before release: a cache returned its own slice and
an eviction loop zeroed it under a live sealer, so fields were sealed under a
32-byte all-zero key. The AAD is reconstructible from the row's own plaintext
columns, so a dump holder could read those payloads with no key at all. That
happened before this code was extracted into its own repository, so it is not
in this repository's history. **Look for more of it**: anywhere a key could be zero, reused, derived
from something guessable, or shared across rows that should differ.

### 2. A blob cannot be moved between tenants, records, or fields

The AAD binds schema version, epoch, leaf, workspace, user, request id and
field name — every part **length-prefixed**, because plain concatenation is
ambiguous: `(workspace 1, user 23)` and `(workspace 12, user 3)` both render
`123`, and that ambiguity is a cross-tenant splice that would pass the tag
check.

Find any two distinct bindings whose blobs are interchangeable and you have a
cross-tenant read. `FuzzRoundTripBindsEveryField` hunts this; the
digit-shifting case is seeded explicitly.

### 3. Compromising every writer yields at most one key lifetime, never history

Writers hold a public key only. If you can make a writer decrypt anything it
did not just seal — or make it leak a private key it should never have — that
is claim 3 broken. Look at `LeafSealer` and what crosses the `Keyring`
interface boundary.

### 4. With `Envelope.AuthKey`, someone who can write to storage cannot forge a row

The capture key is public, so **without** an `AuthKey` anyone with write access
can plant a row that opens as any tenant's — that is documented, and
`TestAuthKey_WithoutOneAStorageWriterCanForge` pins it so the docs stay honest.
**With** one, the field key is `HKDF(salt=AuthKey, ikm=leaf key, info=AAD)`,
under a domain separator distinct from the unauthenticated mode.

If you can make a reader configured with an `AuthKey` accept a row you
produced without that key — by downgrading it to the unauthenticated mode,
by a leaf key of your choosing, or any other way — that is claim 4 broken.

### 5. The two errors are not interchangeable

`ErrKeyUnavailable` means *retry*; `ErrUndecryptable` means *report this*. An
input that produces the wrong one is a real finding, not a nitpick: a
thirty-second keyring blip reading as data corruption sends someone chasing a
phantom, and a genuine decryption bug reading as "try again" means nobody ever
looks. An error outside the declared set is worse — every caller's
`errors.Is` switch takes no branch at all.

The pre-release audit found three of these, now fixed and pinned by tests: an
empty sealed leaf reported *retry* although no retry could supply one; a
wrong-length key reached `Open` and returned an undeclared error; and a leaf
blob wrapping a key of the wrong length (anyone with the public key can make
one) was returned as if it were a key.

`ErrPlaintextTooLarge` and `ErrInvalidConfig` are not part of this pair: they
report a mistake in the calling code, never a property of a row. A **row**
that produces either is a finding.

### 6. Compression before encryption leaks nothing across tenants

We compress then encrypt, deliberately: ciphertext is incompressible, so
sealing raw payloads defeats storage-engine compression and inflates what you
store severalfold.

The CRIME/BREACH objection needs attacker-chosen plaintext compressed
*alongside* a secret in one context. Here every field of every record is
compressed independently, so no tenant's input shares a compression context
with another tenant's anything. **If you can construct a case where it does**,
that is claim 6 broken — and it is the claim we would least like to be wrong
about, because the reasoning is ours rather than a primitive's.

Compressed *length* is observable from the ciphertext. We do not pad, and we
do not claim to hide payload size.

### 7. Post-quantum at the wrapping step, and hybrid on purpose

Leaf keys are wrapped with ML-KEM-768 + X25519 (X-Wing) via `crypto/hpke`. Not
because AES-256 needs it, but because the *ciphertext outlives the policy*: a
payload sealed today sits in a backup for years, and a classical KEM at the
wrapping step is a standing invitation to harvest now and decrypt later.

Hybrid rather than pure ML-KEM because ML-KEM is young: X-Wing holds if
*either* component does. A finding that the hybrid is assembled wrongly — such
that breaking one component suffices — is severe and in scope.

### 8. A compression bomb is refused, not measured

The decoder is constructed with a memory ceiling, so an over-cap payload is
refused *before* allocation. A decoder that inflates first and checks after
has already allocated what the attacker asked for, so one crafted row OOMs the
reader. If you can make `Open` allocate more than its cap, that is a
denial-of-service finding.

### 9. The format is what SPEC.md says it is

[`SPEC.md`](SPEC.md) describes every byte, and `testdata/vectors.json` holds
known-answer vectors that `TestVectors` checks through every intermediate
value. An independent implementation that follows the spec and disagrees with
a vector is a finding against one of the two, and we want to know which.

## What is not a finding

Please read the README's *What scuttle does not protect* and SECURITY.md's *Scope*
first. In short: memory on the writer, metadata, an authorised reader
reading, a single process holding both halves of the keypair, forgery by a
storage writer when no `AuthKey` is configured, deletion of rows, and the lack
of forward secrecy against theft of the capture seed are all documented
non-properties. Reporting them tells us only that the docs are
accurate.

## One genuine design hazard, stated plainly

Every field in `Binding` is **write-once on the stored record**. Re-parenting a
record to another tenant, or renumbering a user, makes its payloads
permanently unreadable. That is the anti-splice property working as intended —
but it means a migration that rewrites those columns is a data-loss operation,
and we would rather you learn that here than from a migration.
