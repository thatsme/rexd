# Contributing

This guide covers setting up Rexd locally, the test suite and its reference
tools, and the checks a change is expected to pass.

## Setup

```sh
git clone https://github.com/thatsme/rexd.git
cd rexd
mix deps.get
mix test
```

### Reference tools

Wire compatibility is checked against two external programs:

- `rdiff` from librsync 2.x, for signatures, deltas and patches;
- `b2sum` from the BLAKE2 reference tools or GNU coreutils, for BLAKE2b-256.

Install them with `brew install librsync b2sum` on macOS or
`apt-get install rdiff coreutils` on Debian and Ubuntu. When a tool is not on
`PATH`, `mix test` prints a warning and skips the tests tagged with its name
(`:rdiff`, `:b2sum`). The committed vectors in `test/fixtures/vectors.term`
still exercise wire compatibility without them.

## Test suite

| Area | Where | What it catches |
|------|-------|-----------------|
| Properties | `test/rexd/*_test.exs` | round-trips over random data, edits and chunkings |
| Oracle | tests tagged `:rdiff`, `:b2sum` | any byte-level divergence from librsync or BLAKE2 |
| Committed vectors | `test/fixtures/vectors.term` | the same, where the tools are absent |
| Adversarial | `test/rexd/adversarial_test.exs` | corrupted and hostile signatures and deltas, including mutation fuzzing |
| In-place | `test/rexd/in_place_test.exs` | dependency ordering, cycle breaking, hostile dependency graphs |
| Doctests | module documentation | examples drifting from the API |

A bug fix comes with a test that fails without it. Tests that guard a
performance bound (for example the hostile-graph tests) are checked by
temporarily removing the optimisation they protect and confirming they fail.

### Minimum versions

Rexd supports Elixir 1.17 on OTP 26 and later. Those versions can be tested
in a container (Docker, OrbStack or any compatible runtime):

```sh
docker run --rm -v "$PWD":/src:ro -w /work \
  hexpm/elixir:1.17.0-erlang-26.0-debian-bookworm-20260610-slim bash -c '
    apt-get update -qq && apt-get install -y -qq rdiff > /dev/null
    cp -r /src/. /work && rm -rf /work/_build /work/deps
    mix local.hex --force && mix local.rebar --force
    mix deps.get && mix test'
```

### Regenerating generated files

- `scripts/gen_vectors.exs` rewrites `test/fixtures/vectors.term`; it needs
  `rdiff` and `b2sum`.
- `scripts/gen_prototab.exs` rewrites `lib/rexd/delta/prototab.ex` from a
  librsync checkout's `src/prototab.c`.

Both outputs are deterministic and committed.

## Checks

Continuous integration runs these on every change; running them locally first
saves a round trip:

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix credo --strict
mix dialyzer
mix docs --warnings-as-errors
```

## Principles

**librsync is the specification.** Where documentation, including this
repository's, disagrees with librsync's source, librsync is right. Behaviour
that differs from librsync without affecting the wire format is recorded in
`NOTES.md`.

**Untrusted input never raises.** Decoding and patching return error tuples
for any byte sequence; streams raise only `Rexd.StreamError`. Time and memory
stay bounded for hostile signatures and deltas. Changes to those paths extend
`test/rexd/adversarial_test.exs`.

**No runtime dependencies.** Development and test dependencies are fine;
`mix deps.tree --only prod` lists Rexd alone.

**Performance changes are measured.** Code shaped for speed rather than
directness carries a short comment and an entry in `NOTES.md` with the direct
form it replaces and the measured difference. Benchmarks live in `bench/`, and
`BENCH.md` records their results.

## Questions and reports

Questions and bug reports go to GitHub issues. Security issues follow
[SECURITY.md](SECURITY.md) instead.
