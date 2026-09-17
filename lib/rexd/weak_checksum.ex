defmodule Rexd.WeakChecksum do
  @moduledoc """
  The interface shared by the rolling checksums, `Rexd.RabinKarp` and
  `Rexd.Rollsum`.

  `window/1` precomputes whatever a checksum needs for windows of a given
  length; `rotate/5` and `rollout/4` receive those two values back, so the
  delta search can slide either checksum without knowing which one it holds.
  """

  @doc "Checksums a binary from scratch."
  @callback hash(binary()) :: non_neg_integer()

  @doc "Constants for windows of `n` bytes."
  @callback window(n :: non_neg_integer()) :: {non_neg_integer(), non_neg_integer()}

  @doc "Slides a window one byte: `out` leaves, `in_byte` enters."
  @callback rotate(
              sum :: non_neg_integer(),
              out :: byte(),
              in_byte :: byte(),
              non_neg_integer(),
              non_neg_integer()
            ) :: non_neg_integer()

  @doc "Removes the oldest byte, shrinking the window to the length of the constants."
  @callback rollout(sum :: non_neg_integer(), out :: byte(), non_neg_integer(), non_neg_integer()) ::
              non_neg_integer()
end
