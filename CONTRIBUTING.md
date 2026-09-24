# Contributing

Thanks for looking. The most valuable contribution is a **broken claim**:
read [ATTACK.md](ATTACK.md). Security findings go through
[SECURITY.md](SECURITY.md), never a public issue or pull request.

## Setup

Go 1.26.1 or newer (`crypto/hpke` and ML-KEM live in the standard library).

```bash
go vet ./...
gofmt -l .                     # must print nothing
go test -race -count=1 ./...
go test -run=^$ -fuzz=FuzzRoundTripBindsEveryField -fuzztime=5m
```

## Rules for changes

- **Test first.** A fix arrives with a test that failed before it. For a
  property ("no two bindings are interchangeable"), prefer a fuzz target that
  asserts the invariant over a single example.
- **Format changes are loud.** If `TestVectors` or `TestSpec_*` fails, you have
  changed the wire format. That needs a new version string (SPEC.md §7), an
  update to SPEC.md, regenerated vectors (`go test -run TestVectors
  -update-vectors`), and a **Format** entry in CHANGELOG.md. Never regenerate
  vectors just to make a test pass.
- **Errors are part of the API.** A row-caused failure is `ErrUndecryptable` or
  `ErrKeyUnavailable`; see ATTACK.md claim 5 for why the distinction matters.
- **New fuzz targets** go in `fuzz_test.go`, in both fuzz jobs in
  `.github/workflows/ci.yml`, and in the table in ATTACK.md. Tests enforce all
  three.
- **Dependencies**: the standard library and `klauspost/compress`, nothing
  else. All cryptography comes from the standard library; `TestGoMod_DependsOnlyOnTheCompressor`
  enforces it. A new dependency needs a reason strong enough to change that test.
- **CI actions** are pinned to a full commit SHA with the tag in a comment.

## Translations

The README exists in seven languages. English is the source; update it first
and note in your pull request which translations are now stale. Code blocks,
API names and diagrams stay byte-identical (a test checks the code blocks); the
tagline lines of the ASCII banner may be translated, the logo may not.

By contributing you agree your contribution is licensed under the
[Apache License 2.0](LICENSE).
