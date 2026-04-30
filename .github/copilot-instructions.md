# Copilot Instructions for `unchained`

`unchained` is a Go library providing password hashers compatible with
[Django's password hashers](https://docs.djangoproject.com/en/stable/topics/auth/passwords/).
It is used both to encode new hashes and to validate passwords from legacy or shared
Django databases. Module path: `github.com/alexandrevicenzi/unchained`.

## Build / Test

- Run all tests: `go test -v ./...`
- Run tests for a single hasher package: `go test -v ./pbkdf2`
- Run a single test by name: `go test -v ./pbkdf2 -run TestPBKDF2SHA256`
- Vet: `go vet ./...`

There is no separate build step (library only). CI historically ran `go test -v ./...`
across multiple Go versions (see `.travis.yml`); `go.mod` currently declares `go 1.24`.

## Architecture

The repo is a flat collection of subpackages, one per hash family:

- `argon2/`, `bcrypt/`, `md5/`, `pbkdf2/`, `sha1/` — each implements a `*Hasher` type
  with `Encode(password, salt, ...) (string, error)` and
  `Verify(password, encoded) (bool, error)` methods, plus `NewXxxHasher()` constructors
  that return Django-compatible defaults (algorithm name, iterations, sizes, etc.).
- Top-level `unchained.go` is the public façade. It defines hasher identifier
  constants (e.g. `PBKDF2SHA256Hasher = "pbkdf2_sha256"`), and dispatches to the
  appropriate subpackage in `CheckPassword` / `MakePassword` based on the algorithm
  prefix in the encoded string. `IdentifyHasher` parses that prefix.
- `rnd.go` provides `GetRandomString` used as the default salt generator.

Encoded password format follows Django: `<algorithm>$<params>$<salt>$<hash>` (argon2
adds extra `$`-separated fields). When adding/changing a hasher, both `Encode` output
and `Verify` parsing must stay byte-compatible with Django, and the dispatch switch
in `unchained.go` plus `IsValidHasher` / `IsHasherImplemented` / `IsWeakHasher` lists
must be updated together.

## Conventions

- Each subpackage exports its own sentinel errors (e.g. `ErrHashComponentMismatch`,
  `ErrAlgorithmMismatch`) prefixed with `unchained/<pkg>:` in the message. Reuse this
  pattern for new hashers rather than returning ad-hoc `errors.New`.
- Hash comparisons use constant-time equality (`crypto/subtle.ConstantTimeCompare` or
  `hmac.Equal`). Do not introduce plain `==` / `bytes.Equal` for hash digests.
- `Encode` accepts `iterations int` (PBKDF2) where `<= 0` means "use the hasher's
  default". Preserve this convention; callers (incl. `MakePassword`) rely on passing `0`.
- `BCrypt` cannot honor a caller-supplied salt (limitation of `x/crypto/bcrypt`); the
  `salt` parameter is intentionally ignored. Don't "fix" this.
- Crypt is deliberately unimplemented (UNIX-only) but kept in `IsValidHasher` so
  Django-encoded `crypt$...` strings are recognized and return `ErrHasherNotImplemented`
  rather than `ErrInvalidHasher`. Keep this distinction when touching the dispatch.
- Tests live alongside code as `*_test.go` in each subpackage; `example_test.go` and
  `unchained_test.go` at the root cover the façade. Add new test vectors generated
  from a real Django installation to guarantee compatibility.
