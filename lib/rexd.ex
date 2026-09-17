defmodule Rexd do
  @moduledoc """
  The rsync algorithm over binaries, wire-compatible with librsync 2.x.

  The receiver, which holds the old version (the *basis*), computes a
  signature: a weak rolling checksum and a strong hash for each fixed-size
  block. The sender, which holds the new version, slides a window over its
  data, looks each window's weak checksum up in the signature, and confirms
  candidates with the strong hash. Matching windows become copy commands
  that reference basis blocks; bytes in between become literal commands.
  The receiver replays the commands against its basis to rebuild the new
  version. Only the signature and the delta cross the wire, so the cost of
  a transfer scales with what changed rather than with the file size.

  ## Example

      iex> basis = String.duplicate("the quick brown fox jumps over the lazy dog. ", 20)
      iex> new = String.replace(basis, "lazy", "sleepy", global: false)
      iex> signature = Rexd.signature(basis, block_len: 64)
      iex> wire = signature |> Rexd.Signature.encode() |> IO.iodata_to_binary()
      iex> {:ok, received} = Rexd.Signature.decode(wire)
      iex> delta = Rexd.delta(received, new)
      iex> Rexd.patch(basis, delta) == {:ok, new}
      true

  ## Modules

    * `Rexd.Signature`, `Rexd.Delta` - the data structures and their librsync
      wire formats.
    * `Rexd.Stream` - the same operations over enumerables of binaries, in
      bounded memory.
    * `Rexd.InPlace` - rebuilding the new version inside the basis storage.
    * `Rexd.Blake2b` - BLAKE2b-256 in Elixir, the default strong hash, usable
      on its own.
  """

  import Bitwise

  alias Rexd.{Delta, InPlace, Patch, Signature}

  @typedoc "Reasons `patch/3` can fail."
  @type patch_error ::
          {:copy_out_of_range, non_neg_integer(), non_neg_integer()}
          | {:output_too_large, non_neg_integer(), non_neg_integer()}

  @doc """
  Computes the signature of `basis`.

  ## Options

    * `:block_len` - bytes per block, default `2048` (librsync's default for
      an input of unknown size). See `recommended_block_len/1`.
    * `:strong_sum_len` - bytes of the strong hash kept per block: `1..32` for
      BLAKE2b, `1..16` for MD4; defaults to the maximum.
    * `:weak` - rolling checksum, `:rabinkarp` (default) or `:rollsum`.
    * `:strong` - strong hash, `:blake2` (default) or `:md4`.

  See `Rexd.Signature` for the four resulting librsync signature types.

  Raises `ArgumentError` on invalid options.
  """
  @spec signature(binary(), keyword()) :: Signature.t()
  defdelegate signature(basis, opts \\ []), to: Signature, as: :compute

  @doc """
  Computes the delta that turns the basis described by `signature` into `new`.

  The signature's weak-checksum index is built on entry when absent; call
  `Rexd.Signature.build_index/1` once to reuse it across several deltas.

  ## Options

    * `:in_place` - when `true`, the delta can also be applied in place with
      `Rexd.InPlace.patch/4`: copies that would close a dependency cycle are
      sent as literals instead. Default `false`.
  """
  @spec delta(Signature.t(), binary(), keyword()) :: Delta.t()
  def delta(%Signature{} = signature, new, opts \\ []) when is_binary(new) do
    {delta, _stats} = delta_with_stats(signature, new, opts)
    delta
  end

  @doc """
  Like `delta/3`, also returning `Rexd.Delta.Stats` for the delta and the
  search.

      iex> basis = String.duplicate("0123456789abcdef", 4)
      iex> sig = Rexd.signature(basis, block_len: 16)
      iex> {_delta, stats} = Rexd.delta_with_stats(sig, "xyz" <> basis)
      iex> {stats.literal_bytes, stats.copy_bytes, stats.copy_commands}
      {3, 64, 1}
  """
  @spec delta_with_stats(Signature.t(), binary(), keyword()) :: {Delta.t(), Delta.Stats.t()}
  def delta_with_stats(%Signature{} = signature, new, opts \\ []) when is_binary(new) do
    opts = Keyword.validate!(opts, in_place: false)
    {delta, stats} = Delta.compute_with_stats(signature, new)
    in_place(delta, stats, new, Keyword.fetch!(opts, :in_place))
  end

  defp in_place(delta, stats, _new, false), do: {delta, stats}

  defp in_place(delta, stats, new, true) do
    safe = InPlace.make_safe(delta, new)
    counters = Map.take(stats, [:weak_hits, :false_weak_hits])
    {safe, struct(Delta.stats(safe), counters)}
  end

  defp in_place(_delta, _stats, _new, other),
    do: raise(ArgumentError, "in_place must be a boolean, got: #{inspect(other)}")

  @doc """
  Rebuilds the new binary by applying `delta` to `basis`.

      iex> basis = "the quick brown fox jumps over the lazy dog"
      iex> new = "the quick red fox jumps over the lazy dog"
      iex> sig = Rexd.signature(basis, block_len: 8)
      iex> Rexd.patch(basis, Rexd.delta(sig, new))
      {:ok, "the quick red fox jumps over the lazy dog"}

  ## Options

    * `:max_size` - the largest output, in bytes, the call may produce;
      default `:infinity`. Checked before any output is built. Set it when
      the delta comes from an untrusted source.

  ## Errors

    * `{:copy_out_of_range, offset, length}` - a copy command reaches past
      the end of `basis`, typically because the delta was computed against a
      different basis. A delta computed against a different basis of
      sufficient length patches without error and produces wrong output;
      detecting that requires a checksum of the expected result, which the
      librsync format does not carry.
    * `{:output_too_large, size, max_size}` - the output would exceed
      `:max_size`.

  Raises `ArgumentError` on invalid options and `FunctionClauseError` on a
  malformed `Rexd.Delta` struct (a delta returned by `delta/2` or
  `Rexd.Delta.decode/1` is always well-formed).
  """
  @spec patch(binary(), Delta.t(), keyword()) :: {:ok, binary()} | {:error, patch_error()}
  defdelegate patch(basis, delta, opts \\ []), to: Patch, as: :apply_delta

  @doc """
  The block length `rdiff` picks for a basis of `size` bytes: 256 up to
  65 536 bytes, otherwise the integer square root of `size` rounded down to a
  multiple of 128 (librsync `rs_sig_args`).

      iex> Rexd.recommended_block_len(1_000)
      256
      iex> Rexd.recommended_block_len(100_000_000)
      9984
  """
  @spec recommended_block_len(non_neg_integer()) :: pos_integer()
  def recommended_block_len(size) when is_integer(size) and size >= 0 and size <= 65_536, do: 256

  def recommended_block_len(size) when is_integer(size) and size > 65_536,
    do: isqrt(size) &&& bnot(127)

  # Newton's method from above; stops when the estimate no longer decreases.
  defp isqrt(n), do: isqrt(n, n)

  defp isqrt(n, x), do: isqrt(n, x, div(x + div(n, x), 2))

  defp isqrt(_n, x, next) when next >= x, do: x
  defp isqrt(n, _x, next), do: isqrt(n, next)
end
