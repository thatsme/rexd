# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Rexd.signature/2`, `Rexd.delta/2` and `Rexd.patch/3` over binaries.
- `Rexd.Signature` and `Rexd.Delta` encoding and decoding in the librsync 2.x
  wire format (`RS_RK_BLAKE2_SIG_MAGIC` signatures), verified against
  `rdiff` 2.3.4.
- `Rexd.Stream.signature/2`, `Rexd.Stream.delta/2` and `Rexd.Stream.patch/3`
  over enumerables of binaries, with bounded memory, and `Rexd.StreamError`.
- `Rexd.Blake2b`: BLAKE2b-256 in pure Elixir.
- All four librsync signature types, selected with the `:weak` (`:rabinkarp`,
  `:rollsum`) and `:strong` (`:blake2`, `:md4`) options.
- `Rexd.recommended_block_len/1`, matching `rdiff`'s default block length.
- `:max_size` option for patching, bounding the output of untrusted deltas.
- `Rexd.InPlace`: in-place patching following Rasch and Burns, with
  `make_safe/2` and the `:in_place` option of `Rexd.delta/3` on the sender
  and `patch/4` on the receiver. In-place deltas remain ordinary librsync
  deltas.
- `Rexd.Delta.Stats`: literal and copy bytes and command counts, plus search
  counters, from `Rexd.delta_with_stats/2`, `Rexd.Delta.stats/1` and the
  `:on_stats` option of `Rexd.Stream.delta/3`.
