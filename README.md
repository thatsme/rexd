# Rexd

The rsync algorithm as a pure-Elixir library: compute a signature of a
basis, a delta from that signature to new data, and patch the basis with the
delta. Signatures and deltas use the librsync 2.x wire format, so they
interoperate with `rdiff`.

## A primitive, not rsync

Rexd implements the delta-transfer algorithm and nothing around it. It does
not walk directories, transfer file lists, preserve permissions or
timestamps, or open network connections. Callers decide where signatures and
deltas travel (sockets, message queues, distributed Erlang) and where data is
stored. Typical uses are pushing updated artefacts to many devices, syncing
node state snapshots, and keeping working copies in step, each with its own
transport.

## Features

- Wire-compatible with librsync 2.x and `rdiff`: all four signature types
  (RabinKarp or rollsum weak checksums with BLAKE2b or MD4 strong hashes) and
  the librsync delta command format. Verified against `rdiff` and `b2sum`.
- Whole-binary functions and streaming variants over enumerables of binaries,
  with bounded memory.
- Hardened for untrusted input: decoders return error tuples on any byte
  sequence, and patching checks copy ranges and can cap the output size.
- Pure Elixir, no runtime dependencies, no NIFs or ports.

## Installation

Rexd is not yet published on Hex. Add it from Git:

```elixir
def deps do
  [
    {:rexd, github: "thatsme/rexd"}
  ]
end
```

Requires Elixir 1.17 or later and OTP 26 or later.

## Usage

### Binaries

```elixir
# Receiver: sign the basis and send the signature.
signature = Rexd.signature(basis, block_len: 2048)
wire = signature |> Rexd.Signature.encode() |> IO.iodata_to_binary()

# Sender: compute a delta against the received signature.
{:ok, signature} = Rexd.Signature.decode(wire)
delta = Rexd.delta(signature, new)
wire = delta |> Rexd.Delta.encode() |> IO.iodata_to_binary()

# Receiver: rebuild the new version.
{:ok, delta} = Rexd.Delta.decode(wire)
{:ok, ^new} = Rexd.patch(basis, delta, max_size: 1_000_000_000)
```

`Rexd.recommended_block_len/1` returns the block length `rdiff` would choose
for a given input size. `Rexd.delta_with_stats/2` also returns how many bytes
the delta carries as literals and how many it copies from the basis.

### Files and other streams

```elixir
# Signature of a file on disk.
"basis.bin"
|> File.stream!(65_536)
|> Rexd.Stream.signature(block_len: 2048)
|> Stream.into(File.stream!("basis.sig"))
|> Stream.run()

# Delta from new data to a file.
{:ok, signature} = "basis.sig" |> File.read!() |> Rexd.Signature.decode()

signature
|> Rexd.Stream.delta(File.stream!("new.bin", 65_536))
|> Stream.into(File.stream!("update.delta"))
|> Stream.run()

# Patch, reading the basis on demand.
{:ok, basis} = :file.open("basis.bin", [:read, :binary, :raw])

read = fn offset, length ->
  case :file.pread(basis, offset, length) do
    {:ok, data} -> data
    :eof -> <<>>
  end
end

read
|> Rexd.Stream.patch(File.stream!("update.delta", 65_536))
|> Stream.into(File.stream!("rebuilt.bin"))
|> Stream.run()
```

Streaming functions raise `Rexd.StreamError` when their input turns out to
be invalid while the stream is consumed.

### Interoperating with rdiff

Signatures and deltas can be exchanged with `rdiff` in either direction. Pass
the block length and strong hash length explicitly, since `rdiff` otherwise
picks them from the input size. `rdiff -R rollsum -H md4` produces the older
signature type that `Rexd.signature(basis, weak: :rollsum, strong: :md4)`
matches:

```sh
rdiff -b 2048 -S 32 signature basis.bin basis.sig
rdiff delta basis.sig new.bin update.delta
rdiff patch basis.bin update.delta rebuilt.bin
```

## Limitations

- MD4 signatures (`strong: :md4`) are supported for peers on older librsync
  defaults; MD4 is not collision-resistant, so prefer the default BLAKE2b.
- The librsync format carries no checksum of the rebuilt data. A delta
  applied to a different basis of sufficient length produces wrong output
  without an error, so callers should verify a hash of the result.
- With an unkeyed rolling checksum, data crafted against a known signature
  can make every window a weak-checksum hit, slowing delta computation to
  tens of kilobytes per second. See [NOTES.md](NOTES.md).
- Patching writes a new copy; in-place patching is not supported.

## Documentation

- [NOTES.md](NOTES.md): format details, differences from librsync, handling
  of untrusted input, and code shaped by performance.
- [BENCH.md](BENCH.md): throughput and memory measurements.
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT. See the `LICENSE` file.
