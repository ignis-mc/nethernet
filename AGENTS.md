# Agent guide for `nethernet`

`nethernet` is a pure-Mojo implementation of NetherNet, the WebRTC
data-channel transport used by Minecraft: Bedrock Edition. It has no C, no
libc calls and no Python: the only way out of the process is the raw Linux
system-call wrapper in `src/nethernet/os/_sys/`.

This file is the single source of truth for coding agents. `CLAUDE.md` only
points here.

## Toolchain

- Mojo is pinned to **1.2.x** (`pixi.toml`). Run everything through
  `pixi run <task>`, or put a Mojo 1.2 `mojo` on `PATH`.
- Tasks: `pixi run test`, `pixi run format`, `pixi run format-check`,
  `pixi run lint-docs`, `pixi run build`, `pixi run bench`,
  `pixi run interop` (needs Go).
- One test file: `mojo run -I src -D ASSERT=all test/nethernet/crypto/test_sha256.mojo`.
  The test binary accepts `--only <names…>`, `--skip <names…>`, `--skip-all`.
- After every edit, compile and run the affected test file. Do not report a
  change as working without that output.
- Do not change the Mojo pin without running the whole suite.

## Mojo 1.2 rules

Load the `mojo-syntax` skill (`.agents/skills/mojo-syntax/`) before writing
Mojo. It tracks nightly; where it disagrees with the 1.2 compiler, the
compiler wins. Known 1.2 differences from the skill:

- `Layout[T](count=n)`, not `length=`.
- `OptionalPointer` / `OptionalMutPointer` aliases are current.
- `lambda` exists.
- `read` is a hard error; the default convention is `imm` and is not written.

Language rules that apply everywhere:

1. `def` only (`fn` is gone). Declare every new variable with `var`. Mark
   every function that can raise with `raises`, and only those.
2. `comptime` replaces `alias` and `@parameter if`. `comptime assert` goes
   inside a function body.
3. Conventions: `mut`, `var`, `out`, `deinit`, `ref`. Lifecycle methods are
   `__init__(out self, …)`, `__init__(out self, *, copy: Self)`,
   `__init__(out self, *, deinit move: Self)`, `__deinit__(deinit self)`.
4. Write `Self.T` for struct parameters inside the struct.
5. Types are `Copyable` but not `ImplicitlyCopyable` unless the copy is O(1).
   Copy with `.copy()`, transfer with `^`.
6. Stdlib imports use the `std.` prefix. Import explicit names, sorted; no
   `import *`.
7. Use `Writable.write_to`, `String(x)` and t-strings (`t"got {n} bytes"`).
8. Prefer `Optional[T]` over sentinels; unwrap with
   `if case .Some(x) = opt:` or `match`.
9. No async, no threads, no globals, no Python interop. The library is
   single-threaded and driven by explicit `now_ms` timestamps.

Idioms verified on 1.2.0 in this repo:

```mojo
def parse(data: Span[UInt8, _]) raises -> UInt16: ...      # borrowed bytes in
def encode(self, mut out: List[UInt8]): ...                 # append to caller's buffer
var digest = Array[UInt8, 32](fill=0)                       # fixed-size value
var view = Span(my_list)[2:5]                               # no-copy slice
var copy = List[UInt8](view)                                # owned copy
var wide = UInt128(a) * UInt128(b)                          # 64x64 -> 128
comptime _TABLE = _make_table()                             # built by the compiler
ref table = global_constant[_TABLE]()                       # one static copy (std.builtin.globals)
trait Hash(Copyable, Defaultable, Deinitable): ...          # generic code needs `Deinitable`
def hmac[H: Hash](key: Span[UInt8, _], ...) -> Array[UInt8, H.DIGEST_SIZE]: ...
```

- A typed error (`raises Errno`) converts automatically when called from a
  plain `raises` function.
- Integer arithmetic wraps on fixed-width types; conversions between integer
  types are always explicit (`UInt32(x)`).
- An `Array[UInt8, size_of[UInt32]()]` does not unify with
  `Array[UInt8, 4]`; build fixed arrays by hand instead of `as_bytes`.

## Architecture

```text
src/nethernet/
  wire.mojo        byte reader and put_* encoders (no dependencies)
  os/              clock, random, UDP/TCP sockets, poll; os/_sys = raw syscalls
  crypto/          hashes, HMAC, AES-GCM, P-256/P-384, ECDSA, X.509, CRCs, base64
  stun/  ice/      STUN codec; ICE agent (host candidates, checks, nomination)
  dtls/            DTLS 1.2 client and server (ECDHE-ECDSA-AES128-GCM-SHA256)
  sctp/            SCTP association over DTLS (RFC 9260 subset + PR-SCTP + RECONFIG)
  datachannel/     DCEP and the two NetherNet channels
  sdp/             the SDP subset NetherNet uses, candidates
  signaling/       signal codec, error codes, identity, HTTP endpoint
  discovery/       LAN discovery on UDP 7551
  conn.mojo, dialer.mojo, listener.mojo   the public transport API
```

- Sub-packages depend only downward in the order listed. `wire` and `crypto`
  never import `os`.
- Protocol code is **sans-I/O**: parsers read `Span[UInt8, _]`, encoders
  append to a caller-owned `mut out: List[UInt8]`, state machines take
  `now_ms: Int` and hand back packets and events. Only `os/`, `conn.mojo`,
  `dialer.mojo`, `listener.mojo`, `discovery/` and `signaling/endpoint*`
  touch sockets.
- Every system call lives in `src/nethernet/os/_sys/linux.mojo`. Wrappers
  borrow their buffers (`Span`, `mut` arguments) so the owner stays alive
  across the call; never pass `Int(x.unsafe_ptr())` of a local whose last use
  is that expression. Linux x86-64 and aarch64 only.
- Inside `src/nethernet`, import relatively (`from .sha256 import Sha256`,
  `from ..crypto.hmac import hmac`). Tests, examples and benchmarks import
  absolutely (`from nethernet.crypto.sha256 import sha256`).
- Private modules, fields and functions start with `_`. There is no access
  control in Mojo; the underscore is the contract.

## Quality bar

- Every public symbol has a docstring in the stdlib format (summary sentence,
  then `Parameters:`, `Args:`, `Returns:`, `Raises:` as applicable).
  `pixi run lint-docs` must pass.
- `pixi run format` before committing; 80 columns; never hand-format.
- Naming: `snake_case` functions and variables, `PascalCase` types and type
  parameters, `SCREAMING_SNAKE_CASE` module constants.
- Each module `src/nethernet/a/b.mojo` has `test/nethernet/a/test_b.mojo`
  with `def test_*() raises` functions and this `main`:

  ```mojo
  def main() raises:
      TestSuite.discover_tests[__functions_in_module()]().run()
  ```

- Crypto needs published test vectors (FIPS, RFC, Wycheproof), constant-time
  comparison of secrets (`crypto.ct.constant_time_eq`) and no secret-dependent
  branches or table indices where practical. Document every exception.
- Wire formats are checked against captures from pion / go-nethernet under
  `interop/`. A protocol change needs an interop run (`pixi run interop`).
- Bug fixes come with a reproducing test.
- Keep comments short and about why. Hacks get `TODO(#issue)`.
- Do not edit `.agents/skills/` by hand (`npx skills update`). Do not commit
  agent notes or scratch files.
