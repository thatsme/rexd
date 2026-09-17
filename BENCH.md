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

Input MiB per second over 20 MiB:

| Operation | MiB/s |
|-----------|------:|
| RabinKarp rolling update | 96.0 |
| BLAKE2b-256, 2 KiB blocks | 63.6 |
| `Rexd.signature/2` | 54.6 |
| `Rexd.Stream.signature/2` | 55.4 |
| `Rexd.delta/2`, unrelated data | 32.4 |
| `Rexd.delta/2`, identical data | 54.1 |
| `Rexd.delta/2`, 100 scattered edits | 54.1 |
| `Rexd.delta/2`, all-zero data | 56.2 |
| `Rexd.Stream.delta/2`, unrelated data | 31.9 |
| `Rexd.Stream.delta/2`, 100 scattered edits | 53.8 |

- **Signature** speed is set by BLAKE2b, which runs once over every basis
  block.
- **Delta** has two regimes. Where data matches the basis, the window jumps
  a block at a time and pays one BLAKE2b per block, so it runs close to
  signature speed. Where nothing matches, the window rolls one byte at a time
  and pays a map lookup per byte; that is the slowest ordinary case, about
  32 MiB/s. Mixed data falls between the two.
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
| whole-binary | `Rexd.signature/2` | 35.8 MiB | 167 KiB |
| whole-binary | `Rexd.delta/2`, edited | 29.7 MiB | 55 KiB |
| whole-binary | `Rexd.delta/2`, unrelated | 31.5 MiB | 0 KiB |
| whole-binary | `Rexd.patch/3` (output 100 MiB) | 582 KiB | 100.0 MiB |
| streaming | `Rexd.Stream.signature/2` | 514 KiB | 603 KiB |
| streaming | `Rexd.Stream.delta/2` | 20.3 MiB | 326 KiB |
| streaming | `Rexd.Stream.patch/3` | 465 KiB | 639 KiB |

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
