# Unchained

[![Go Reference](https://pkg.go.dev/badge/github.com/alexandrevicenzi/unchained.svg)](https://pkg.go.dev/github.com/alexandrevicenzi/unchained)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexandrevicenzi/unchained)](https://goreportcard.com/report/github.com/alexandrevicenzi/unchained)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

Secure password hashers for Go that are wire-compatible with
[Django Password Hashers](https://docs.djangoproject.com/en/stable/topics/auth/passwords/).

`unchained` lets a Go service:

- Generate password hashes that Django (1.x – 5.x) can validate.
- Validate passwords stored in a legacy or shared Django database.

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Supported Hashers](#supported-hashers)
- [Django Compatibility Matrix](#django-compatibility-matrix)
- [Usage with Django 1.x](#usage-with-django-1x)
- [Usage with Django 5.x](#usage-with-django-5x)
- [End-to-End Examples (Go ↔ Django)](#end-to-end-examples-go--django)
- [API Reference](#api-reference)
- [Error Reference](#error-reference)
- [Notes & Limitations](#notes--limitations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## Install

Requires Go 1.24+.

```sh
go get github.com/alexandrevicenzi/unchained
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/alexandrevicenzi/unchained"
)

func main() {
    // Encode (default = pbkdf2_sha256, the same hasher Django uses by default)
    encoded, err := unchained.MakePassword("my-password", "", "default")
    if err != nil {
        panic(err)
    }
    fmt.Println(encoded)
    // pbkdf2_sha256$1200000$<salt>$<base64-hash>

    // Verify
    ok, err := unchained.CheckPassword("my-password", encoded)
    fmt.Println(ok, err) // true <nil>
}
```

`MakePassword(password, salt, hasher)`:

- `password` — plain text. Empty string returns an unusable password (`"!" + random`).
- `salt` — explicit salt, or empty to auto-generate via `GetRandomString(12)`. Ignored by BCrypt.
- `hasher` — algorithm identifier (see below) or `"default"` (= `pbkdf2_sha256`).

`CheckPassword(password, encoded)` auto-detects the algorithm from the encoded prefix.

## Supported Hashers

| Hasher | Identifier | Encode | Decode | Dependencies |
|:--|:--|:-:|:-:|:--|
| Argon2 (argon2i + argon2id) | `argon2`        | ✅ | ✅ | [`x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) |
| BCrypt                | `bcrypt`        | ✅ | ✅ | [`x/crypto/bcrypt`](https://pkg.go.dev/golang.org/x/crypto/bcrypt) |
| BCrypt SHA256         | `bcrypt_sha256` | ✅ | ✅ | [`x/crypto/bcrypt`](https://pkg.go.dev/golang.org/x/crypto/bcrypt) |
| Crypt                 | `crypt`         | ✘ | ✘ | — (UNIX only, not planned) |
| MD5                   | `md5`           | ✅ | ✅ | — |
| PBKDF2 SHA1           | `pbkdf2_sha1`   | ✅ | ✅ | [`x/crypto/pbkdf2`](https://pkg.go.dev/golang.org/x/crypto/pbkdf2) |
| **PBKDF2 SHA256** ⭐   | `pbkdf2_sha256` | ✅ | ✅ | [`x/crypto/pbkdf2`](https://pkg.go.dev/golang.org/x/crypto/pbkdf2) |
| SHA1                  | `sha1`          | ✅ | ✅ | — |
| Unsalted MD5          | `unsalted_md5`  | ✅ | ✅ | — |
| Unsalted SHA1         | `unsalted_sha1` | ✅ | ✅ | — |
| Scrypt                | `scrypt`        | ✘ | ✘ | (Django 4.0+ only, not implemented) |

⭐ Django's default hasher across every supported version (1.x through 5.x).

## Django Compatibility Matrix

The encoded format `<algorithm>$<params>$<salt>$<hash>` is identical across Django
versions. `unchained` parses iteration counts/parameters out of the encoded string,
so verification is independent of the iteration defaults of any specific Django version.

| Algorithm | Django 1.x | Django 5.x | Notes |
|---|:-:|:-:|---|
| `pbkdf2_sha256` (default) | ✅ | ✅ | Verifies any iteration count |
| `pbkdf2_sha1`   | ✅ | ✅ | |
| `bcrypt`        | ✅ | ✅ | Salt argument ignored (limitation of `x/crypto/bcrypt`) |
| `bcrypt_sha256` | ✅ | ✅ | |
| `argon2`        | ✅ | ✅ | Both **argon2i** (Django 1.10–3.0) and **argon2id** (Django 3.1+) verified; argon2d is not supported |
| `md5` / `sha1`  | ✅ | ✅ | Weak — verification only |
| `unsalted_md5`  | ✅ | ✅ | Weak — verification only |
| `unsalted_sha1` | ✅ | ⚠️ | Hasher removed from Django 5.1, but existing hashes still verify here |
| `crypt`         | ❌ | ❌ | Not implemented; removed from Django 4.0 |
| `scrypt`        | — | ❌ | Not implemented (Django 4.0+) |

> Both **argon2i** and **argon2id** encoded hashes are supported on `Verify`,
> which auto-detects the variant from the encoded string. `MakePassword` with
> the `"argon2"` identifier produces **argon2id** (matching Django 3.1+ defaults).

## Usage with Django 1.x

Django 1.x defaults to `PBKDF2PasswordHasher` (PBKDF2-SHA256). Iteration count varies
by minor release (e.g. 1.11 → 36,000) but is parsed from the encoded string at verify
time, so no special handling is needed.

### Encode for a Django 1.x database

```go
encoded, err := unchained.MakePassword("S3cret!", "", "default")
// encoded -> pbkdf2_sha256$1200000$<salt>$<base64-hash>
// Write `encoded` directly into auth_user.password
```

### Verify a hash from a Django 1.x database

```go
encoded := "pbkdf2_sha256$36000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag="

ok, err := unchained.CheckPassword("admin", encoded)
switch {
case err != nil:
    fmt.Println("verification error:", err)
case ok:
    fmt.Println("password OK")
default:
    fmt.Println("password mismatch")
}
```

## Usage with Django 5.x

Django 5.x still defaults to `PBKDF2PasswordHasher`, but the default iteration count
has grown to **1,200,000** (5.1+). The encoded format is unchanged, so verification
"just works".

### Encode at Django 5.x's default work factor

`MakePassword` defaults to `PBKDF2Hasher.Iterations = 1,200,000`, matching
Django 5.1+'s default. To use a different iteration count, drop down to the
`pbkdf2` sub-package:

```go
import (
    "github.com/alexandrevicenzi/unchained"
    "github.com/alexandrevicenzi/unchained/pbkdf2"
)

func encodeWithCustomIterations(password string, iterations int) (string, error) {
    h := pbkdf2.NewPBKDF2SHA256Hasher()
    salt := unchained.GetRandomString(unchained.DefaultSaltSize)
    return h.Encode(password, salt, iterations)
}
```

> Hashes generated with a lower iteration count are still valid in Django 5.x —
> Django will accept them and re-hash to its current default on the user's next login.

### Verify a hash from a Django 5.x database

```go
encoded := "pbkdf2_sha256$1200000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag="
ok, err := unchained.CheckPassword("admin", encoded)
```

### Argon2id support

`unchained` supports both `argon2i` and `argon2id`. `Verify` auto-detects the
variant from the encoded string, so hashes produced by Django 3.1+ (which
default to `argon2id`) are validated transparently. When generating new hashes
from Go, `MakePassword(pw, "", unchained.Argon2Hasher)` produces `argon2id`
output with Django 5.x-compatible defaults (memory=102400 KiB, time=2,
parallelism=8). To force argon2i (legacy Django ≤ 3.0), use
`argon2.NewArgon2iHasher()` directly.

Argon2d remains unsupported — Django doesn't use it either, so this only
matters for non-Django-generated hashes.

## End-to-End Examples (Go ↔ Django)

### Go encodes → Django authenticates

```go
encoded, _ := unchained.MakePassword("S3cret!", "", "default")
db.Exec(`UPDATE auth_user SET password = $1 WHERE username = $2`, encoded, "alice")
```

```python
# Django side
user = authenticate(username="alice", password="S3cret!")  # ✅
```

### Django encodes → Go authenticates

```python
# Django shell
from django.contrib.auth.hashers import make_password
print(make_password("S3cret!"))
# pbkdf2_sha256$1200000$xxxxxxxx$yyyyyy=
```

```go
ok, err := unchained.CheckPassword("S3cret!", encodedFromDjango)
```

## API Reference

Top-level helpers (`unchained` package):

| Function | Purpose |
|---|---|
| `MakePassword(password, salt, hasher string) (string, error)` | Encode a password using the given hasher (or `"default"`) |
| `CheckPassword(password, encoded string) (bool, error)`       | Verify a password against an encoded hash |
| `IdentifyHasher(encoded string) string`                       | Return the algorithm identifier of an encoded hash |
| `IsValidHasher(hasher string) bool`                           | True if `hasher` is one Django knows about |
| `IsHasherImplemented(hasher string) bool`                     | True if this library can use it |
| `IsWeakHasher(hasher string) bool`                            | True for MD5/SHA1/Crypt/Unsalted variants |
| `IsPasswordUsable(encoded string) bool`                       | False for empty or `!`-prefixed unusable passwords |
| `GetRandomString(n int) string`                               | Cryptographically random salt generator |

Sub-packages each export a `New<Algo>Hasher()` constructor returning a typed
hasher with `Encode` / `Verify` methods, e.g.:

```go
pbkdf2.NewPBKDF2SHA256Hasher().Encode(password, salt, iterations)
argon2.NewArgon2Hasher().Verify(password, encoded)
bcrypt.NewBCryptSHA256Hasher().Encode(password, "")
```

Use these directly when you need to control parameters that the top-level
`MakePassword` doesn't expose (PBKDF2 iterations, Argon2 memory/time/threads, …).

## Error Reference

| Error | Meaning | Typical cause |
|---|---|---|
| `unchained.ErrInvalidHasher` | Unknown algorithm prefix | Corrupt or non-Django string |
| `unchained.ErrHasherNotImplemented` | Django-known but unsupported here | `crypt`, `scrypt` |
| `pbkdf2.ErrHashComponentMismatch` | Wrong number of `$` segments | Truncated string |
| `pbkdf2.ErrSaltContainsDollarSign` | `$` in user-supplied salt | Use a `$`-free salt (alias `ErrSaltContainsDollarSing` retained for back-compat) |
| `argon2.ErrAlgorithmMismatch` | Encoded prefix isn't `argon2$` | Wrong hasher dispatched |
| `argon2.ErrUnsupportedVariant` | argon2 sub-algo is `argon2d` | argon2d isn't supported |
| `argon2.ErrIncompatibleVersion` | argon2 version mismatch | Hash from a newer argon2 spec |
| `(false, nil)` from `CheckPassword` | Password wrong, or `!`-prefixed unusable hash | — |

## Notes & Limitations

- **Crypt** is intentionally unimplemented (UNIX-only). Encoded `crypt$...` hashes
  return `ErrHasherNotImplemented` rather than `ErrInvalidHasher`.
- **Argon2** supports both `argon2i` and `argon2id`. `argon2d` is not supported
  (and is not used by Django).
- **BCrypt** ignores the `salt` argument; bcrypt manages its own salt internally
  (limitation of `golang.org/x/crypto/bcrypt`). Encoding the same password twice
  yields different hashes — both are valid.
- **PBKDF2 default iterations** is `1,200,000`, matching Django 5.1+'s default.
  Use the `pbkdf2` sub-package's `Encode` with an explicit `iterations` value
  to target a different Django version.
- **Scrypt** (Django 4.0+) is not implemented.

## Testing

Run the full test suite:

```sh
go test -v ./...
```

Test a single hasher sub-package:

```sh
go test -v ./pbkdf2
go test -v ./argon2
```

Run a specific test by name:

```sh
go test -v ./pbkdf2 -run TestPBKDF2SHA256
```

Lint the code:

```sh
go vet ./...
```

Tests are located alongside code in each sub-package (`*_test.go` files) and at the
root (`unchained_test.go`, `example_test.go`). Most tests verify compatibility with
hashes generated by real Django installations. When adding new hashers or modifying
existing ones, generate fresh test vectors from Django and add them to the relevant
test file.

## Contributing

Contributions are welcome! If you find a bug, want to add support for a new hasher, or
improve documentation, please open an issue or pull request.

### Before submitting a PR:

1. **Add test vectors** from a real Django installation if your change involves hash
   encoding/decoding. Include both the exact command used to generate the vector and
   the Django version.
2. **Run the full test suite**: `go test -v ./...`
3. **Ensure compatibility**: Test against both legacy (Django 1.x) and modern (Django
   5.x) hash formats.
4. **Update documentation** if you change the public API or add a new hasher.

### Guidelines:

- Use constant-time equality (`crypto/subtle.ConstantTimeCompare` or `hmac.Equal`) for
  hash comparisons — never plain `==` or `bytes.Equal`.
- Define hasher-specific sentinel errors in the sub-package (e.g.
  `ErrHashComponentMismatch`); prefix messages with `unchained/<pkg>:`.
- Keep the dispatch logic in `unchained.go` in sync with the helper functions
  (`IsValidHasher`, `IsHasherImplemented`, `IsWeakHasher`, `IdentifyHasher`).
- BCrypt has an inherent constraint (salt argument ignored) — document this
  clearly but don't try to "fix" it without a design discussion first.

## License

BSD

## References

- [Password management in Django (stable)](https://docs.djangoproject.com/en/stable/topics/auth/passwords/)
- [Django 1.11 password docs](https://docs.djangoproject.com/en/1.11/topics/auth/passwords/)
- [Django 5.1 password docs](https://docs.djangoproject.com/en/5.1/topics/auth/passwords/)
- [Django source: `django/contrib/auth/hashers.py`](https://github.com/django/django/blob/main/django/contrib/auth/hashers.py)
- [Django Unchained](https://www.imdb.com/title/tt1853728/) :trollface:

## Related Links

- [Django-compatible signing for Go (`django.core.signing`)](https://gitlab.com/pennersr/djgo/)
