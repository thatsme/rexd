defmodule Rexd.Rollsum do
  @moduledoc false
  # The adler-style rolling checksum of librsync's older signature types
  # (`RS_MD4_SIG_MAGIC`, `RS_BLAKE2_SIG_MAGIC`).
  #
  # Two 16-bit sums are kept over a window of `n` bytes, each byte counted with
  # an offset of 31 (`ROLLSUM_CHAR_OFFSET` in `rollsum.h`):
  #
  #     s1 = Σ (b_i + 31)                     (mod 2^16)
  #     s2 = Σ (n − i) · (b_i + 31)           (mod 2^16)
  #     digest = s2 · 2^16 + s1
  #
  # The functions mirror `Rexd.RabinKarp` so the delta search can use either
  # checksum: `window/1` returns the per-length constants, here the window
  # length itself, and `rotate/5` and `rollout/4` take them.

  import Bitwise

  @behaviour Rexd.WeakChecksum

  @mask 0xFFFF
  @char_offset 31

  @doc "Checksums `data` from scratch."
  @impl true
  @spec hash(binary()) :: non_neg_integer()
  def hash(data) when is_binary(data), do: sums(data, 0, 0)

  defp sums(<<byte, rest::binary>>, s1, s2) do
    s1 = s1 + byte + @char_offset &&& @mask
    sums(rest, s1, s2 + s1 &&& @mask)
  end

  defp sums(<<>>, s1, s2), do: digest(s1, s2)

  @doc "The constants for a window of `n` bytes: the length itself."
  @impl true
  @spec window(non_neg_integer()) :: {non_neg_integer(), 0}
  def window(n) when is_integer(n) and n >= 0, do: {n, 0}

  @doc """
  Slides a window of `n` bytes one byte forward: `out` leaves, `in_byte`
  enters. `n` comes from `window(n)`.
  """
  @impl true
  @spec rotate(non_neg_integer(), byte(), byte(), non_neg_integer(), 0) :: non_neg_integer()
  def rotate(sum, out, in_byte, n, _unused) do
    s1 = (sum &&& @mask) + in_byte - out &&& @mask
    s2 = (sum >>> 16) + s1 - n * (out + @char_offset) &&& @mask
    digest(s1, s2)
  end

  @doc """
  Removes the oldest byte `out`, shrinking the window from `n + 1` to `n`
  bytes, where `n` comes from `window(n)`.
  """
  @impl true
  @spec rollout(non_neg_integer(), byte(), non_neg_integer(), 0) :: non_neg_integer()
  def rollout(sum, out, n, _unused) do
    s1 = (sum &&& @mask) - (out + @char_offset) &&& @mask
    s2 = (sum >>> 16) - (n + 1) * (out + @char_offset) &&& @mask
    digest(s1, s2)
  end

  defp digest(s1, s2), do: s2 <<< 16 ||| s1
end
