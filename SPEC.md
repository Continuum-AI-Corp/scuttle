# scuttle wire format

This document describes scuttle's stored format precisely enough to write an
independent implementation. It is **v0 and not stable**: a change is recorded in
[CHANGELOG.md](CHANGELOG.md) and reflected in the version strings below.

Known-answer vectors are in [`testdata/vectors.json`](testdata/vectors.json).
`TestVectors` checks every intermediate value in them (opened leaf key,
associated data, field key, plaintext) against this implementation. A change to
any of them is a format change.

Notation: `||` is concatenation; `u32be(n)` is `n` as 4 bytes, big-endian;
`str(x)` is the UTF-8 bytes of `x`; `dec(i)` is the base-10 ASCII rendering of
the integer `i` (with a leading `-` if negative, no padding, no `+`).

## 1. Keys

| Key | Size | Who holds it | Stored with rows |
|---|---|---|---|
| Capture seed | 32 bytes | Readers only | Never |
| Capture public key | 1216 bytes | Every writer | No (public) |
| Auth key (optional) | 32 bytes, not all zero | Writers and readers | Never |
| Leaf key | 32 bytes | The writer that minted it, for its lifetime | Only wrapped (§2) |

The capture key pair is the HPKE KEM `MLKEM768-X25519` (X-Wing) from
draft-ietf-hpke-pq, as implemented by Go's `crypto/hpke`. The seed is the KEM's
private key encoding; the public key is its public key encoding.

**Generation id**: `kem_key_id = hex(SHA-256(public key)[0:8])`, 16 lowercase
hex characters. It names a capture-key generation, it is not secret, and it is
not bound cryptographically: the HPKE open is what fails for the wrong key.
Stripping it can only force the fallback in §2 (one decapsulation per
generation held), never yield a wrong key — ML-KEM decapsulation under the
wrong key returns an implicit-rejection secret the attacker cannot predict, so
the HPKE tag fails.

## 2. Sealed leaf

A writer draws 32 random bytes as the leaf key and wraps it with single-shot
HPKE in **base mode**:

- KEM: `MLKEM768-X25519`
- KDF: `HKDF-SHA256`
- AEAD: `AES-256-GCM`
- info: `str("orca/rlog/leaf/v1") || str("|") || str(leaf_id)`
- aad: empty
- plaintext: the 32-byte leaf key

`blob = enc || ct`, where `enc` is the 1120-byte encapsulated key and `ct` is
48 bytes (32-byte key + 16-byte tag). Total: 1168 bytes.

A stored record carries `(leaf_id, kem_key_id, blob)`. `leaf_id` must be
1 to 256 bytes.

**Opening.** A reader:

1. Fails with *undecryptable* if `leaf_id` or `blob` is empty, or `leaf_id` is
   longer than 256 bytes.
2. If `kem_key_id` is set: uses that generation, or fails with *undecryptable*
   if it does not hold it. If `kem_key_id` is empty (rows predating the stamp):
   tries every generation it holds, active first, and takes the first that
   opens — unless configured to require the stamp, in which case it fails with
   *undecryptable*.
3. Fails with *undecryptable* if the HPKE open fails, or if the opened
   plaintext is not exactly 32 bytes, or is 32 zero bytes.

Base mode authenticates no sender: anyone with the public key can produce a
valid blob wrapping a key of their choice. In the authenticated mode (§4) that
does not matter, because the field key also depends on the auth key. In the
unauthenticated mode it does: such a blob keys a row that opens as genuine.

## 3. Associated data

For a binding `(schema_version, epoch_id, leaf_id, workspace_id, user_id,
request_id)` and a field name:

```
parts = [ str(prefix),
          dec(schema_version),
          str(epoch_id),
          str(leaf_id),
          dec(workspace_id),
          dec(user_id),
          str(request_id),
          str(field) ]

aad = u32be(len(parts[0])) || parts[0] || ... || u32be(len(parts[7])) || parts[7]
```

`prefix` is `"orca/rlog/v1"` in the unauthenticated mode and
`"orca/rlog/v1/auth"` in the authenticated mode.

`str(x)` is the raw bytes of `x`: no Unicode normalisation or validation, so
implementations must pass strings through byte for byte. Integers are signed
64-bit, rendered in decimal. Each part is shorter than 2^32 bytes (a leaf id is
at most 256).

`leaf_id` here must equal the sealed leaf's `leaf_id`. A mismatch is not
dangerous — the tag fails — but such a record can never be opened.

Length-prefixing makes the encoding injective: `(workspace 1, user 23)` and
`(workspace 12, user 3)` produce different bytes.

Every binding component is **write-once** on the stored record. Changing any of
them makes the record's fields permanently unreadable.

The binding is only as specific as its values: records with equal bindings can
swap field blobs. `request_id` must therefore be unique per stored record.
Columns outside the binding are not authenticated.

Defined field names (part of the format; add, never rename):
`request_body`, `response_body`, `error_message`, `request_headers`,
`response_headers`.

## 4. Field key

- **Unauthenticated mode** (no auth key):
  `field_key = HKDF-Expand(SHA-256, prk = leaf_key, info = aad, L = 32)`
- **Authenticated mode**:
  `field_key = HKDF(SHA-256, ikm = leaf_key, salt = auth_key, info = aad, L = 32)`,
  i.e. `HKDF-Expand(HMAC-SHA256(auth_key, leaf_key), aad, 32)`.

The two modes differ in both the pseudorandom key and the `info` (§3), so they
derive the same field key only with negligible probability.

In the authenticated mode the PRK is a PRF output under the 256-bit auth key,
so a forger who chooses the leaf key still cannot compute the field key, and
forging a tag is as hard as forging AES-GCM under an unknown key.

A reader configured for the authenticated mode **must not** fall back to the
unauthenticated one; otherwise a forger writes unauthenticated rows.

## 5. Field ciphertext

```
packed = zstd(plaintext)           // one independent zstd frame per field
nonce  = 12 random bytes
blob   = nonce || AES-256-GCM-Seal(field_key, nonce, packed, aad)
```

The 16-byte GCM tag is at the end. Minimum blob length is 28 bytes.

**Stored (uncompressed) frames.** A writer may store a field uncompressed, to
make its length independent of its content (see the README on compression). It
is still a standard zstd frame, so readers treat it like any other:

```
28 B5 2F FD                         magic
A0                                  single segment, 4-byte content size
u32le(len(plaintext))               content size
blocks of at most 128 KiB, each:    u24le(size << 3 | 0 << 1 | last) || bytes
```

An empty plaintext is one last block of size 0. The packed size is
`9 + len(plaintext) + 3 × max(1, ceil(len(plaintext) / 131072))`.

**Nonces.** Nonces are random, and a field key is used again only when the same
binding and field are sealed again. Keep that far below 2^32 times per
(binding, field); in practice a record is sealed once.

**Key commitment.** AES-GCM is not key-committing. That does not matter here:
each field has exactly one candidate key, and the only multi-key trial (the §2
fallback) happens inside HPKE, where a wrong key fails.

**Size cap.** Both sides share a cap `max` (default 1 MiB; at most 16 MiB).
A writer **must** refuse a plaintext longer than `max`. A reader **must** refuse
output longer than `max` and **must** bound decoder memory by the cap, not just
by the 16 MiB ceiling: scuttle decodes under a limit of the next power of two at
or above `max(2 × max, 64 KiB)` (at most 16 MiB), which covers the window any
frame the writer produced can declare.

**Opening** fails with *undecryptable* if the blob is shorter than 28 bytes, the
tag does not verify, decompression fails, or the output exceeds `max`.

## 6. Errors

An implementation should expose the same distinction:

| Condition | Meaning |
|---|---|
| *undecryptable* | The record will not open as presented. No retry helps. |
| *key unavailable* | Key material could not be reached right now (remote keyring down, request cancelled). Retry. |
| *plaintext too large* | The writer was given a body over the cap. Nothing was written. |
| *invalid configuration* | The caller's configuration is wrong. Never caused by a record. |

## 7. Versioning

The format version is carried in three places, all of which are bound into the
cryptography rather than stored as a free-standing byte:

- `"orca/rlog/v1"` / `"orca/rlog/v1/auth"` — the field-key derivation and AAD.
- `"orca/rlog/leaf/v1"` — the HPKE info for sealed leaves.
- `Binding.SchemaVersion` — the application's own record version, in the AAD.

A reader must know which **mode** to open a record with, and must not learn it
from the record: every stored value is writable by the adversary this format
defends against. A deployment uses one mode for all records it reads; moving
from the unauthenticated mode to the authenticated one means re-sealing the
existing records (scuttle's `Reseal`), not reading both. A re-sealing
migration cannot distinguish forged records from real ones, so the forgery
window lasts until it finishes; readers stay on the unauthenticated mode until
then and switch all at once. Changing any of the
strings above is a breaking format change.
