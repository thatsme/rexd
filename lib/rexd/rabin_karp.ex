defmodule Rexd.RabinKarp do
  @moduledoc false
  # The RabinKarp rolling hash used as the weak checksum in librsync 2.x
  # signatures (`RS_RK_BLAKE2_SIG_MAGIC`).
  #
  # The hash of a window `b_0 .. b_(n-1)` is the polynomial
  #
  #     SEED·MULT^n + b_0·MULT^(n-1) + ... + b_(n-1)    (mod 2^32)
  #
  # with `SEED = 1` and `MULT = 0x08104225`, matching `rabinkarp.h`. Bytes are
  # hashed as-is, with no per-byte offset.
  #
  # Sliding the window drops `out` and appends `in`. Because the seed term moves
  # up one power with every appended byte, removing `out` also subtracts
  # `MULT^n·(MULT − 1)`, which librsync writes as `MULT^n·(out + ADJ)` with
  # `ADJ = MULT − 1`.
  #
  # Both `MULT^n` and `MULT^n·ADJ` depend only on the window length, so callers
  # precompute them once with `window/1` and pass them to `rotate/5` and
  # `rollout/4`. The per-byte work is then `h·MULT` (below 2^59.01) and
  # `MULT^n·out` (below 2^40): no bignum is built on the rolling path except
  # for the rare `h·MULT` whose `h` lies within about 1% of 2^32.
  #
  # The multiplication `h·MULT` is deliberately left whole. Splitting it into
  # 16-bit halves keeps every product small but measured about 35% slower,
  # because the rare bignum costs less than the extra arithmetic on every byte.

  import Bitwise

  @behaviour Rexd.WeakChecksum

  @mask 0xFFFFFFFF
  @seed 1
  @mult 0x08104225
  @adj 0x08104224

  @typedoc "An unsigned 32-bit weak checksum."
  @type t :: 0..0xFFFFFFFF

  @typedoc "Per-window-length constants: `{MULT^n, MULT^n·ADJ}`, both mod 2^32."
  @type window :: {0..0xFFFFFFFF, 0..0xFFFFFFFF}

  @doc "The initial hash of an empty window."
  @spec seed() :: t()
  def seed, do: @seed

  @doc "Hashes `data` from scratch."
  @impl true
  @spec hash(binary()) :: t()
  def hash(data) when is_binary(data), do: update(@seed, data)

  @doc "Appends every byte of `data` to the hash `h` (librsync `rabinkarp_update`)."
  @spec update(t(), binary()) :: t()
  def update(h, <<b, rest::binary>>), do: update(h * @mult + b &&& @mask, rest)
  def update(h, <<>>), do: h

  @doc "Appends a single byte (librsync `rabinkarp_rollin`)."
  @spec rollin(t(), byte()) :: t()
  def rollin(h, in_byte), do: h * @mult + in_byte &&& @mask

  @doc "Precomputes the constants for a window of `n` bytes."
  @impl true
  @spec window(non_neg_integer()) :: window()
  def window(n) when is_integer(n) and n >= 0 do
    mult_n = pow(n)
    {mult_n, mult_n * @adj &&& @mask}
  end

  @doc """
  Slides a window of `n` bytes one byte forward: `out` leaves, `in_byte`
  enters. `mult_n` and `adj_n` come from `window(n)`.
  """
  @impl true
  @spec rotate(t(), byte(), byte(), non_neg_integer(), non_neg_integer()) :: t()
  def rotate(h, out, in_byte, mult_n, adj_n) do
    h * @mult + in_byte - mult_n * out - adj_n &&& @mask
  end

  @doc """
  Removes the oldest byte `out` from a window, shrinking it from `n + 1` to
  `n` bytes. `mult_n` and `adj_n` come from `window(n)`, the length after
  removal (librsync `rabinkarp_rollout`).
  """
  @impl true
  @spec rollout(t(), byte(), non_neg_integer(), non_neg_integer()) :: t()
  def rollout(h, out, mult_n, adj_n), do: h - mult_n * out - adj_n &&& @mask

  @doc "`MULT^n mod 2^32`."
  @spec pow(non_neg_integer()) :: 0..0xFFFFFFFF
  def pow(n) when is_integer(n) and n >= 0, do: pow(@mult, n, 1)

  # Square-and-multiply over the bits of n.
  defp pow(_base, 0, acc), do: acc

  defp pow(base, n, acc) when (n &&& 1) == 1,
    do: pow(base * base &&& @mask, n >>> 1, acc * base &&& @mask)

  defp pow(base, n, acc), do: pow(base * base &&& @mask, n >>> 1, acc)
end
