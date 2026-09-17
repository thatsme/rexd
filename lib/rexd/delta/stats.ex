defmodule Rexd.Delta.Stats do
  @moduledoc """
  Statistics about a delta and the search that produced it.

    * `literal_bytes`, `literal_commands` - data carried in the delta itself.
    * `copy_bytes`, `copy_commands` - data taken from the basis.
    * `weak_hits` - windows whose weak checksum appeared in the signature; each
      costs one strong hash.
    * `false_weak_hits` - weak hits whose strong hash matched no block.

  `literal_bytes + copy_bytes` is the size of the rebuilt data. The search
  counters are `nil` when the statistics are computed from a delta alone
  (`Rexd.Delta.stats/1`), since the search is not known then.

  A high `false_weak_hits` relative to the input size points to data crafted
  against the signature (see the notes on untrusted input) or to a very short
  `strong_sum_len` being unnecessary: false hits cost time, not correctness.
  """

  defstruct literal_bytes: 0,
            literal_commands: 0,
            copy_bytes: 0,
            copy_commands: 0,
            weak_hits: nil,
            false_weak_hits: nil

  @type t :: %__MODULE__{
          literal_bytes: non_neg_integer(),
          literal_commands: non_neg_integer(),
          copy_bytes: non_neg_integer(),
          copy_commands: non_neg_integer(),
          weak_hits: non_neg_integer() | nil,
          false_weak_hits: non_neg_integer() | nil
        }

  @doc false
  @spec add_commands(t(), [Rexd.Delta.command()]) :: t()
  def add_commands(%__MODULE__{} = stats, commands), do: Enum.reduce(commands, stats, &add/2)

  defp add({:literal, data}, stats),
    do: %{
      stats
      | literal_bytes: stats.literal_bytes + byte_size(data),
        literal_commands: stats.literal_commands + 1
    }

  defp add({:copy, _offset, len}, stats),
    do: %{stats | copy_bytes: stats.copy_bytes + len, copy_commands: stats.copy_commands + 1}
end
