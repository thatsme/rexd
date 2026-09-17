# Implementation notes

Details of the librsync 2.x formats that are easy to get wrong, and the
places where Rexd deliberately differs from librsync's behaviour while
staying wire-compatible. The reference is librsync 2.3.4.

## Strong hash: BLAKE2b-256, not truncated BLAKE2b-512

librsync computes the strong sum with `blake2b_init(&ctx, 32)` and truncates
the 32-byte digest to `strong_sum_len` when writing the signature
(`checksum.c`, `mksum.c`). BLAKE2b's digest length is part of the parameter
block that initialises the state, so BLAKE2b-256 is a different function from
BLAKE2b-512 cut to 32 bytes:

| input `"hello world, this is rexd"` | digest                         |
|-------------------------------------|--------------------------------|
| BLAKE2b-256 (`b2sum -l 256`, rdiff) | `47a606efd8e7de0a…9d2695069118168` |
| BLAKE2b-512, first 32 bytes         | `7ebc49b54860a1dd…0ba0703902bb11` |

OTP's `:crypto` exposes BLAKE2b only with a 64-byte digest and no length
parameter, so `Rexd.Blake2b` implements BLAKE2b-256 in Elixir.

BLAKE2b works on 64-bit words. BEAM small integers hold 60 bits, so direct
64-bit arithmetic allocates a bignum on nearly every addition and rotation.
`Rexd.Blake2b` carries each word as two 32-bit halves, with carries propagated
by hand, and unrolls all twelve rounds at compile time. On an Apple Silicon
laptop (OTP 28, JIT) this runs at about 63 MB/s over 2 KiB blocks, against
about 5 MB/s for the direct 64-bit version.

## RabinKarp weak checksum

From `rabinkarp.h`: `SEED = 1`, `MULT = 0x08104225`, arithmetic mod 2^32.

- Bytes are hashed as-is. There is no per-byte offset.
- Sliding the window is `h·MULT + in − MULT^n·(out + ADJ)` with
  `ADJ = MULT − 1`. The `ADJ` term removes the seed's contribution, which
  moves up one power of `MULT` with every appended byte. A rolling update
  without it is internally consistent (rolling and from-scratch results agree
  with each other if both omit the seed) but does not match librsync.
- `MULT^n mod 2^32` and `MULT^n·ADJ mod 2^32` depend only on the window
  length and are computed once. Inside the loop the only products are `h·MULT`
  (below 2^59.01, which exceeds the small-integer limit only when `h` is
  within about 1% of 2^32) and `MULT^n·out` (below 2^40).

## Block length

`rdiff` does not use a fixed default. With `-b 0`, its default, it applies
`rs_sig_args`: 256 bytes for inputs up to 65 536 bytes, otherwise the integer
square root of the input size rounded down to a multiple of 128.
`Rexd.recommended_block_len/1` reproduces that choice. `Rexd.signature/2`
defaults to 2048 (`RS_DEFAULT_BLOCK_LEN`, librsync's value when the input size
is unknown), because a signature may be computed before the size is known.

The signature format does not record the basis length, so a decoded
signature cannot tell whether its last block is short.

## Delta command encoding

The opcode table is generated from `prototab.c` (`scripts/gen_prototab.exs`).
Encoding follows `emit.c`:

- literals of 1 to 64 bytes put the length in the opcode (`0x01`–`0x40`);
- longer literals use `LITERAL_N1`/`N2`/`N4`, whichever is smallest;
- copy commands choose the offset width and the length width independently.

librsync bounds the size of a literal command and so never emits
`LITERAL_N8`. Rexd emits a single literal per unmatched run, which uses
`LITERAL_N8` only above 4 GiB. Both decoders accept it.

`Rexd.Delta.decode/1` rejects bytes after the END command, and rejects what
librsync's patcher (`patch.c`) reports as a corrupt stream: zero-length
literal or copy commands, and 8-byte arguments of 2^63 or more, which
librsync reads as negative signed integers.

`Rexd.patch/3` checks every copy against the basis length and computes the
output size before building any output. A delta of a few kilobytes can
describe gigabytes of output through repeated copies, so `:max_size` bounds
it for deltas from untrusted sources.

## Delta search

The search follows `delta.c`: a full-block window rolls one byte at a time
until its weak checksum is found in the signature and its strong hash
confirms a block; a match emits a copy and restarts the window after it;
contiguous copies are merged; at the end of the input the window shrinks from
the front so that a short last block can still match.

Differences, none of which affect the wire format:

- **Continuation preference.** When a window matches several identical basis
  blocks, Rexd picks the block that directly follows the previous copy, if it
  matches. librsync picks the first block its hash table returns. On repetitive
  input such as runs of zero bytes, Rexd therefore emits one long copy where
  librsync emits one copy per block. On the committed test vectors the encoded
  deltas are otherwise byte-identical to `rdiff`'s.
- **Short windows only against the last block.** Only the last basis block can
  be shorter than `block_len`, so shrinking end-of-input windows are compared
  against that block alone. librsync compares them against every block with a
  matching weak checksum, which can only succeed through a hash collision.
- **Literals reference the input.** Literal commands are sub-binaries of the
  new data, not copies.

## Code shaped by performance

A few places favour speed over the most direct form of the code. Each is
listed here with the direct form it replaces and the measured difference, and
carries a short comment at the code site.

Measurements: Apple Silicon laptop, Elixir 1.19 / OTP 28 with the JIT,
random data, `block_len` 2048, `strong_sum_len` 32.

| Where | Readable form | Kept form | Gain |
|-------|---------------|-----------|------|
| `Rexd.Blake2b` | state in a tuple, `g/7` per round | rounds unrolled at compile time into variable bindings | 3.4 → 5.1 MB/s |
| `Rexd.Blake2b` | 64-bit words | each word as two 32-bit halves | 5.1 → 63.1 MB/s |
| `Rexd.Delta.Search.scan/4` | classify every window, then record the result | misses handled inline | 32.6 → 35.7 MB/s on unmatched data |
| `Rexd.Delta.Search.advance/4` | `ctx.field` for each value | one destructuring match | 26.5 → 32.6 MB/s on unmatched data |
| `Rexd.RabinKarp.rotate/5` | constants recomputed per step | `MULT^n` and `MULT^n·ADJ` passed in | avoids bignum products on every byte |

The reverse trade was also made once. The delta search was first written as
a single loop with nine positional arguments, which ran at 43.7 MB/s on
unmatched data. It was restructured around the `Context` and `Output`
structs for clarity at a cost of about 18%, since the result stays well above
the 20 MB/s design target.

One apparent optimisation was rejected: splitting `h·MULT` in RabinKarp into
16-bit halves to avoid occasional bignums measured 305 MB/s against 473 MB/s
for the plain product.
