# Security policy

Rexd processes signatures and deltas that usually come from another machine,
so it treats them as untrusted input.

## Supported versions

Security fixes are released for the latest minor version of the current major
version.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting: the **Security** tab of the repository, then **Report a
vulnerability**. Please do not open a public issue for a suspected
vulnerability.

A useful report includes the Rexd, Elixir and OTP versions, the function
called, and an input that reproduces the problem (an encoded signature or
delta as hex is ideal).

## What counts as a vulnerability

- An exception other than `ArgumentError` for invalid options, or
  `Rexd.StreamError` from a stream, when decoding or applying a signature or
  delta.
- Time or memory that grows beyond the documented bounds for a crafted
  signature or delta.
- `Rexd.patch/3` or `Rexd.Stream.patch/3` producing output larger than
  `:max_size`, or reading outside the basis.
- `Rexd.InPlace.patch/4` writing to storage before rejecting a delta it
  rejects.
- A delta produced by Rexd that does not rebuild the new data it was computed
  from.

## Known limitations

These are documented properties of the design rather than vulnerabilities:

- **Crafted weak-checksum collisions.** Data built against a known signature
  can make every window a weak-checksum hit, slowing delta computation to
  tens of KiB per second. The output stays correct. See
  [NOTES.md](NOTES.md#untrusted-input).
- **No integrity check of the result.** The librsync format carries no
  checksum of the rebuilt data. A delta applied to a different basis of
  sufficient length produces wrong output without an error; verify a hash of
  the result where that matters.
- **MD4 signatures.** MD4 is not collision-resistant. The older signature
  types exist for compatibility; the default uses BLAKE2b.
- **Unbounded output by default.** `:max_size` defaults to `:infinity`; set
  it for deltas from untrusted sources.
- **Interrupted in-place patching.** Stopping `Rexd.InPlace.patch/4` part-way
  leaves the storage unusable.
