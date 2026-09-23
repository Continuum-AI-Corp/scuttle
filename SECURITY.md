# Reporting a vulnerability

Report privately, by either channel:

- **Email [security@orcarouter.ai](mailto:security@orcarouter.ai).**
- **GitHub private vulnerability reporting**: the *Security* tab →
  *Report a vulnerability*. It stays private until we publish an advisory.

Include what you did, what you expected, what happened, and — if you have
one — a failing test or fuzz input. A reproduction in the form of a Go test
against this repository is the fastest thing to act on.

Please do not open a public issue or a pull request for a finding that lets
someone read data they should not.

## Supported versions

scuttle is v0. Fixes land on `main` and in the next `v0.x.y` release; older v0
releases are not patched. The wire format may change between minor versions,
and CHANGELOG.md says when it does.

| Version | Supported |
|---|---|
| latest `v0.x` release and `main` | ✅ |
| anything older | ❌ |

## Timeline

These are targets, not guarantees, and we will tell you if we miss one:

- **Acknowledge** your report within **3 business days**.
- **Assess** it — confirmed, duplicate, out of scope, or disagreed with, and why —
  within **10 business days**.
- **Fix and disclose** in coordination with you. We aim to publish a fix and an
  advisory within **90 days** of your report, sooner for anything that lets
  someone read data. If we need longer we will say why and agree a date with
  you; if we go quiet, you are free to disclose.

## What we will do

- **Acknowledge** that we received it.
- **Tell you what we think it is** — confirmed, already known, out of scope, or
  we disagree and why. If we disagree we will say so plainly rather than
  letting the report go quiet.
- **Credit you** in the advisory and the changelog unless you ask us not to.

There is **no bug bounty** and no payment. Anyone offering one on our behalf is
not us.

## Scope

In scope: this repository's code, its wire format, and the claims in
[ATTACK.md](ATTACK.md).

Out of scope, because the library says so itself (see the README's *What scuttle
does not protect*):

- **Plaintext in the writer's memory.** Payloads are plaintext in RAM by
  construction. A core dump or an eBPF probe on a live writer sees them.
- **Metadata.** Timestamps, sizes, model names, status codes and identifiers
  stay plaintext, because they are what you query on.
- **An authorised reader reading.** Access control belongs to the application.
- **A single process holding both keys.** An in-process keyring is not
  write-only, and the README says so. Reporting that a binary holding the
  private key can decrypt is not a finding.
- **Forgery without `AuthKey`.** With no `Envelope.AuthKey`, anyone who can
  write to storage can insert a row that decrypts as genuine. That is the
  documented unauthenticated mode. Forgery *with* an `AuthKey` configured is
  in scope and serious.
- **Deletion or rollback of rows.** Encryption cannot detect a missing row.
- **Theft of the capture seed.** It is a root secret with no forward secrecy;
  whoever holds it opens what it sealed.
- **Rows written by a compromised writer.** It holds the `AuthKey`.
- **Columns outside `Binding`**, and records that share a `Binding`: neither
  is authenticated, and the README says so.
- **The length of a compressed field.** Compression is a length oracle within
  a field; `Envelope.DisableCompression` is the documented remedy.

Everything else — including anything in ATTACK.md that turns out to be false —
is in scope.

## Status

**v0. Not independently audited. The wire format is not stable.** Do not adopt
this for data you cannot afford to lose or to have become unreadable. If you
are reading this file because you are evaluating it for production: the honest
answer today is *wait, or audit it yourself*.
