# webdavd — a lightweight WebDAV server

`webdavd` is a small, memory-frugal WebDAV (RFC 4918, class 1) server written in
C++20. It runs *behind* nginx: TLS, request-size limits, rate limiting and DDoS
protection are the reverse proxy's job, so `webdavd` only ever speaks plain
HTTP and never implements TLS itself.

Status: **complete class 1 implementation** (OPTIONS, GET, HEAD, PUT, DELETE,
MKCOL, PROPFIND, PROPPATCH, COPY, MOVE). Request bodies and file responses are
streamed with fixed-size buffers; no request body is ever accumulated in
memory.

## Building

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Presets: `release`, `asan` (`-fsanitize=address,undefined`), `coverage`
(`--coverage`). Third-party dependencies (nlohmann/json, GoogleTest, Boost.Asio
+ Boost.Beast) are fetched by CMake's `FetchContent`; nothing else is required.

## Running

```sh
./build/release/webdavd --config /etc/webdavd/config.json
./build/release/webdavd --version
```

`webdavd` prints a specific reason to stderr and exits non-zero for every
configuration problem; it never silently falls back to defaults.

## Configuration

See `config.example.json`:

```json
{
  "host": "127.0.0.1",
  "port": 8080,
  "users": [
    { "name": "alice", "password_bcrypt": "$2b$12$…", "root": "/srv/dav/alice" }
  ]
}
```

| Key | Required | Default | Notes |
| --- | --- | --- | --- |
| `host` | yes | — | Must be resolvable |
| `port` | yes | — | 1–65535 |
| `users` | yes | — | Array of `{name, password_bcrypt, root}` |
| `max_connections` | no | 16 | 1–1024 |
| `auth_max_concurrent` | no | 2 | 1–64, bounds concurrent bcrypt work |
| `auth_backoff_base_ms` | no | 250 | 1–60000 |
| `auth_backoff_max_ms` | no | 5000 | ≥ base, ≤ 600000 |

Unknown keys are rejected. Users come **only** from this file: there is no
runtime user management, no environment-variable source and no user-related
command-line flag.

Startup validation rejects, among other things: unresolvable hosts, non-string
or out-of-range values, empty or duplicate user names, non-absolute or missing
roots, roots that are not directories, users whose roots nest inside each
other, and bcrypt hashes that are not `$2a$/$2b$/$2y$` with cost ≥ 10.

Generate a hash with any bcrypt-capable tool, e.g.:

```sh
perl -e 'print crypt("s3cret", q{$2b$12$abcdefghijklmnopqrstuu}), "\n"'
```

## Authentication

HTTP Basic over the nginx-terminated TLS connection. Every request, including
`OPTIONS`, is authenticated. Missing or wrong credentials produce `401` with
`WWW-Authenticate: Basic realm="webdav", charset="UTF-8"`.

* Passwords are stored only as bcrypt hashes (cost ≥ 10).
* Hash comparison is constant-time.
* Unknown users run a dummy bcrypt verification, so they cost the same as a
  wrong password and cannot be told apart by timing.
* Concurrent bcrypt verifications are bounded by a fixed-size semaphore, and
  repeated failures from the same client are met with an escalating, capped
  delay. All bookkeeping lives in fixed-capacity tables.
* Basic credentials are only protected by the TLS reverse proxy; never expose
  `webdavd` directly.

## Supported methods and semantics

| Method / feature | Behaviour |
| --- | --- |
| `OPTIONS` | `200`, `DAV: 1`, `MS-Author-Via: DAV`, `Allow` lists all class-1 methods. |
| `GET` / `HEAD` | Streams regular files. A single valid `Range: bytes=…` returns `206`; malformed or multi-range requests fall back to `200` with the whole entity. Collections return `405`. |
| `PUT` | Streams Content-Length or chunked bodies into a same-directory `O_CREAT|O_EXCL|O_NOFOLLOW` temporary file and atomically `renameat()`s it into place. New resources return `201`, replacements `204`; missing parents return `409`; intermediate failures remove the temporary file. |
| `DELETE` | Deletes files and collections recursively. The root returns `403`. |
| `MKCOL` | Creates one collection. A request body returns `415`; an existing resource or the root returns `405`; a missing parent returns `409`. |
| `PROPFIND` | Supports `Depth: 0` and `Depth: 1`; missing or `infinity` depth returns `403`. Empty body means `allprop`. Unknown properties are reported with `404` in a separate `propstat`. Symlinked entries are omitted from `Depth: 1` listings. |
| `PROPPATCH` | Returns a `207` multistatus with `403 Forbidden` for every named property; dead properties are not stored. |
| `COPY` / `MOVE` | Destination must resolve inside the authenticated user's own root. `Overwrite: F` returns `412` if the destination exists. COPY collections recursively by default; `Depth: 0` copies only the collection itself. Cross-device MOVE falls back to recursive copy + delete. |
| `LOCK`, `UNLOCK` | Class 2 is not implemented: `405` plus `Allow`. |
| `SEARCH`, `PATCH`, `TRACE`, `ACL`, versioning extensions | Not implemented: `405` plus `Allow`. |
| Conditional headers (`If`, `If-Match`, `If-None-Match`) | Not evaluated; requests are processed unconditionally. |
| `Expect: 100-continue` | The server sends the interim response for HTTP/1.1 clients with bodies larger than curl's threshold. |
| `Depth: infinity` PROPFIND | Deliberately rejected with `403` to keep work and response size bounded. |

## Path safety

Every user is confined to their configured root.

* The root is opened once as a directory descriptor. Each request path is
  percent-decoded exactly once and split into segments; operations then walk
  the tree component by component with
  `openat(..., O_PATH|O_NOFOLLOW|O_CLOEXEC)` and hold directory descriptors for
  the actual operation. There is no canonicalise-then-reopen pattern.
* Rejected with `400` or `403` before any filesystem action: malformed
  percent-encoding, NUL bytes, decoded paths longer than 4096 bytes, missing
  leading `/`, empty segments, `.`/`..` segments, encoded slashes (`%2f`/`%2F`)
  and double-encoded input containing `%25`.
* Symlinks are never followed. A symlink in any intermediate segment or as the
  leaf produces `403`. `Depth: 1` directory listings skip symlinks. Recursive
  delete/copy that encounters a symlink stops with `403`/`ELOOP` instead of
  traversing it.
* `Destination` is parsed for COPY/MOVE. A different authority yields `502`.
  A missing or syntactically invalid destination yields `400`; a destination
  that resolves outside the current user's root, or to the root itself, yields
  `403`.
* Error bodies are generic and do not echo server-side absolute paths or other
  users' names.

### TOCTOU review

All file-taking operations use descriptors obtained during resolution:
`open_leaf(parent, leaf, ...)` always adds `O_NOFOLLOW`; `renameat()`,
`unlinkat()`, `mkdirat()` and `fstatat(..., AT_SYMLINK_NOFOLLOW)` are performed
relative to those held descriptors. A concurrent rename or symlink swap can
therefore make an operation fail or land in the already-opened directory inode,
but it cannot make the server follow an attacker-controlled symlink outside the
root. The `DavTest.ConcurrentIntermediateSymlinkSwapCannotEscape` test exercises
this race with a swap loop.

## Memory budget

The hard target is peak RSS below 10 MB with 16 concurrent connections.

| Component | Budget / measurement |
| --- | --- |
| `.text` | 409 KiB |
| `.data` | 23 KiB |
| `.bss` | 16 KiB |
| fixed bookkeeping | one root descriptor per user, 1024 auth-backoff slots, `max_connections` connection slots |
| per connection | 16 KiB header buffer + 16 KiB streaming body/copy buffer + touched thread-stack pages (≈32–64 KiB total, order-of-magnitude) |
| 16 concurrent connections | ≈0.5–1 MiB of buffers on top of the shared image |
| idle process | `VmRSS`/`VmHWM` 4724 kB / ≈4.6 MiB (empty root, no traffic) |
| 16-way memcheck | `VmHWM` 5856 kB / ≈5.7 MiB for 3×512 MiB PUT + 3×512 MiB GET + 1000×PROPFIND Depth:1 + 200×auth |

`scripts/memcheck.sh` reproduces the 16-way load with sparse files and asserts
that `/proc/<pid>/status` `VmHWM` stays below 10 MiB. It prints the observed
value and cleans up its work directory.

## Residual risks / documented limitations

* Application-layer TLS is out of scope. Run behind nginx or another TLS
  reverse proxy and bind to loopback.
* No class 2 locking, ACLs, quotas, SEARCH, versioning or dead-property
  persistence. Clients requiring these features will see `405` or a `PROPPATCH`
  403 response.
* Conditional request headers are ignored. There is also no multi-range,
  `If-Range`, or partial-PUT support.
* Filenames containing a literal `%` cannot be addressed because any `%25` in
  the request target is treated as a possible double-encoding attack. Files
  named with spaces, Chinese characters and other bytes still work when their
  request target is percent-encoded (for example `%20`).
* A failed cross-device MOVE fallback, or a failed recursive COPY, can leave a
  partial destination tree behind; the source is not modified. The partial
  destination must be removed by the client.
* PROPFIND `Depth: 1` streams the response but still walks and renders every
  child. Huge directories consume CPU and network bandwidth; put rate/size
  limits in nginx if that matters.
* The design assumes a trusted local filesystem administrator. A local user who
  can write to a served root can of course create, remove or rename files; the
  confinement guarantees concern remote WebDAV clients.
* Oversized request headers/request lines are rejected by the HTTP parser by
  closing the connection; they do not produce an application-level error body.

## Deployment

Use `nginx.conf.example` as a starting point and `webdavd.service.example` for a
systemd unit. The nginx example:

* turns off request/response buffering;
* disables nginx's body-size limit;
* sets HTTP/1.1 keep-alive to the backend;
* preserves the client `Host` header (`$http_host`) so that an absolute
  `Destination` with the same host and an explicit port still validates; and
* forwards `Authorization`, `Destination`, `Depth`, `Overwrite`, `Translate`
  and conditional headers unchanged.

Do **not** rewrite `Destination` in nginx: `webdavd` validates it against the
authenticated user's root. Also firewall the backend port so only nginx can
reach it.

## Verification / self-check

The repository was delivered with these gates:

```sh
cmake --build --preset release                 # -Wall -Wextra -Wpedantic -Werror
ctest --preset release                         # 155/155 tests passed
ASAN_OPTIONS=detect_leaks=1 ctest --preset asan # 155/155, 0 leaks
./scripts/coverage.sh                          # src/ + include/ 100.0% (1878/1878 lines)
./scripts/memcheck.sh                          # 16-way, VmHWM 5.7 MiB < 10 MiB
```

The detailed final report is in `SELF_CHECK.md`.
