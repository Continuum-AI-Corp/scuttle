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
not bound cryptographically (the HPKE open is what fails for the wrong key).

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
non-empty.

**Opening.** A reader:

1. Fails with *undecryptable* if `leaf_id` or `blob` is empty.
2. If `kem_key_id` is set: uses that generation, or fails with *undecryptable*
   if it does not hold it. If `kem_key_id` is empty (rows predating the stamp):
   tries every generation it holds, active first, and takes the first that
   opens.
3. Fails with *undecryptable* if the HPKE open fails, or if the opened
   plaintext is not exactly 32 bytes.

Base mode authenticates no sender: anyone with the public key can produce a
valid blob wrapping a key of their choice. Section 4 is what stops that from
mattering.

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

Length-prefixing makes the encoding injective: `(workspace 1, user 23)` and
`(workspace 12, user 3)` produce different bytes.

Every binding component is **write-once** on the stored record. Changing any of
them makes the record's fields permanently unreadable.

Defined field names (part of the format; add, never rename):
`request_body`, `response_body`, `error_message`, `request_headers`,
`response_headers`.

## 4. Field key

- **Unauthenticated mode** (no auth key):
  `field_key = HKDF-Expand(SHA-256, prk = leaf_key, info = aad, L = 32)`
- **Authenticated mode**:
  `field_key = HKDF(SHA-256, ikm = leaf_key, salt = auth_key, info = aad, L = 32)`,
  i.e. `HKDF-Expand(HMAC-SHA256(auth_key, leaf_key), aad, 32)`.

The two modes use different `aad` (§3), so they never derive the same key.

A reader configured for the authenticated mode **must not** fall back to the
unauthenticated one; otherwise a forger writes unauthenticated rows.

## 5. Field ciphertext

```
packed = zstd(plaintext)           // one independent zstd frame per field
nonce  = 12 random bytes
blob   = nonce || AES-256-GCM-Seal(field_key, nonce, packed, aad)
```

The 16-byte GCM tag is at the end. Minimum blob length is 28 bytes.

**Size cap.** Both sides share a cap `max` (default 1 MiB; at most 16 MiB).
A writer **must** refuse a plaintext longer than `max`. A reader **must** refuse
to decompress past `max`, and must bound decoder allocation independently of the
cap check (scuttle's decoder is constructed with a 16 MiB memory ceiling).

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

A reader must know which version a record uses before opening it; in practice
the record's plaintext `schema_version` column says so. Changing any of the
strings above is a breaking format change.
