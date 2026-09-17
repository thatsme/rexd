# Benchmarks

Measurements of throughput and memory. All figures come from the scripts in
`bench/`, timed with `:timer.tc` on one scheduler.

## Environment

| | |
|---|---|
| Machine | Apple M5, 10 cores, 24 GiB RAM |
| OS | macOS 26.6.2 |
| Runtime | Elixir 1.19.5, Erlang/OTP 28 with the JIT |
| Data | random bytes unless stated otherwise |
| Parameters | `block_len` 2048, `strong_sum_len` 32, stream chunks of 64 KiB |

## Throughput

```sh
mix run bench/throughput.exs 20
```

Input MiB per second over 20 MiB. The machine mixes performance and
efficiency cores, and single runs vary by more than 2x with the kind of core
the scheduler thread lands on, for seconds at a time. The script therefore
measures the whole table in four interleaved rounds and reports each row's
best run.

| Operation | MiB/s |
|-----------|------:|
| RabinKarp rolling update | 100.1 |
| BLAKE2b-256, 2 KiB blocks | 61.0 |
| `Rexd.signature/2` | 56.9 |
| `Rexd.signature/2`, rollsum + MD4 | 132.3 |
| `Rexd.Stream.signature/2` | 56.3 |
| `Rexd.delta/2`, unrelated data | 30.0 |
| `Rexd.delta/2`, identical data | 55.9 |
| `Rexd.delta/2`, 100 scattered edits | 53.1 |
| `Rexd.delta/2`, all-zero data | 53.6 |
| `Rexd.delta/2`, rollsum + MD4, unrelated data | 30.0 |
| `Rexd.delta/2`, rollsum + MD4, 100 scattered edits | 149.3 |
| `Rexd.Stream.delta/2`, unrelated data | 28.8 |
| `Rexd.Stream.delta/2`, 100 scattered edits | 55.2 |

- **Signature** speed is set by the strong hash, which runs once over every
  basis block. MD4 is more than twice as fast as BLAKE2b-256 here, which is
  why the older signature types sign and match faster; BLAKE2b remains the
  default because MD4 is not collision-resistant.
- **Delta** has two regimes. Where data matches the basis, the window jumps
  a block at a time and pays one strong hash per block, so it runs close to
  signature speed. Where nothing matches, the window rolls one byte at a time
  and pays a map lookup per byte; that is the slowest ordinary case, about
  30 MiB/s. Mixed data falls between the two.
- **Patch** is a memory copy of the output. `Rexd.patch/3` runs at several
  GiB/s and varies with the allocator between runs; streaming patch is
  bounded by how fast the basis can be read and the output written.

### Worst case: crafted weak-checksum collisions

When new data is constructed so that every window's weak checksum appears in
the signature (possible because RabinKarp is unkeyed), every byte costs a
BLAKE2b computation over a whole block. Over 250 KiB of such data,
`Rexd.delta/2` ran at 31.5 KiB/s. The output remains correct. See
[NOTES.md](NOTES.md#untrusted-input).

## Memory

```sh
mix run bench/memory.exs 100
```

A 100 MiB basis and a copy with 100 scattered edits. The whole-binary rows
hold both in memory; the streaming rows read and write files, with the basis
read through `:file.pread/3` during patching. Each figure is the peak above
the level just before the operation, the largest of three runs, sampled every
millisecond. Process heap includes short-lived garbage not yet collected;
binary memory shows whether data is copied.

| Scenario (100 MiB) | Operation | Process heap peak | Binary peak |
|----------|-----------|------------------:|------------:|
| whole-binary | `Rexd.signature/2` | 34.2 MiB | 172 KiB |
| whole-binary | `Rexd.delta/2`, edited | 29.6 MiB | 63 KiB |
| whole-binary | `Rexd.delta/2`, unrelated | 31.5 MiB | 0 KiB |
| whole-binary | `Rexd.patch/3` (output 100 MiB) | 581 KiB | 100.0 MiB |
| streaming | `Rexd.Stream.signature/2` | 504 KiB | 925 KiB |
| streaming | `Rexd.Stream.delta/2` | 20.4 MiB | 326 KiB |
| streaming | `Rexd.Stream.patch/3` | 607 KiB | 651 KiB |

The streamed delta is 201 KiB, and the patched file is verified against the
new file by SHA-256.

- **No copies of the input.** `Rexd.delta/2` allocates no binary memory for
  the new data: literal commands are sub-binaries of it. The only large
  binary allocation in the table is `Rexd.patch/3` building its 100 MiB
  result.
- **Process heap peaks are transient garbage**, not retained state: BLAKE2b
  state tuples during signing, and during delta the occasional RabinKarp
  product that exceeds the small-integer range plus the sub-binaries used for
  strong hashes. They are reclaimed by ordinary garbage collection and do not
  grow with input size. The retained result is small: the signature of a
  100 MiB basis is about 2 MiB, and the delta above has 201 commands.
- **Streaming holds less than 1 MiB of binaries** in each stage, independent
  of the file size.

### Binaries built by appending

A binary produced by repeated `<>` appends keeps spare capacity so that
further appends are cheap. The VM may copy such a binary once, the first time
a sub-binary is taken from it. In these measurements a 100 MiB new version
built that way showed a one-time 100 MiB binary peak on its first
`Rexd.delta/2` in some runs, and none on later runs or after
`:binary.copy/1`. The memory benchmark compacts its input for that reason;
the copy is not made by Rexd.
