defmodule Rexd.Delta do
  @moduledoc """
  A delta: the commands that rebuild a new binary from a basis, and its
  librsync wire encoding.

  Commands are `{:literal, bytes}` (append `bytes`) and
  `{:copy, offset, length}` (append `length` bytes of the basis starting at
  `offset`). Deltas computed by `compute/2` never contain two adjacent
  literals, never contain a copy that directly continues the previous copy,
  and never contain zero-length commands.

  Wire format: u32 `RS_DELTA_MAGIC` (`0x72730236`), then one command per
  opcode byte, then an END byte (`0x00`). The opcode selects the command kind
  and the widths of its big-endian arguments; see `Rexd.Delta.Prototab`,
  generated from librsync's `prototab.c`. Encoding follows librsync's
  `emit.c`: literals of 1..64 bytes carry their length in the opcode, longer
  literals and both copy arguments use the smallest width that fits.
  """

  alias Rexd.Delta.{Prototab, Search}
  alias Rexd.Signature

  @magic 0x72730236

  defstruct commands: []

  @type command :: {:literal, binary()} | {:copy, non_neg_integer(), non_neg_integer()}
  @type t :: %__MODULE__{commands: [command()]}

  @typedoc "Reasons `decode/1` can fail."
  @type decode_error ::
          :truncated_header
          | :truncated
          | :missing_end
          | :trailing_data
          | {:bad_magic, non_neg_integer()}
          | {:reserved_opcode, byte()}

  @typedoc """
  Search counters: `weak_hits` windows whose weak checksum was in the index
  (each costs one strong hash), `false_weak_hits` of those whose strong hash
  matched no candidate.
  """
  @type stats :: %{weak_hits: non_neg_integer(), false_weak_hits: non_neg_integer()}

  @doc "The delta magic number."
  @spec magic() :: non_neg_integer()
  def magic, do: @magic

  @doc "Computes the delta from the basis described by `sig` to `new`. See `Rexd.delta/2`."
  @spec compute(Signature.t(), binary()) :: t()
  def compute(%Signature{} = sig, new) when is_binary(new) do
    {delta, _stats} = compute_with_stats(sig, new)
    delta
  end

  @doc false
  @spec compute_with_stats(Signature.t(), binary()) :: {t(), stats()}
  def compute_with_stats(%Signature{} = sig, new) when is_binary(new) do
    {commands, stats} = Search.run(sig, new)
    {%__MODULE__{commands: commands}, stats}
  end

  # ---------------------------------------------------------------------------
  # Wire format
  # ---------------------------------------------------------------------------

  @table Prototab.table()

  @literal_immediate for {op, :literal, imm, 0, 0} <- @table, imm > 0, into: %{}, do: {imm, op}
  @literal_by_width for {op, :literal, 0, w, 0} <- @table, into: %{}, do: {w, op}
  @copy_by_widths for {op, :copy, 0, w1, w2} <- @table, into: %{}, do: {{w1, w2}, op}
  @max_immediate @literal_immediate |> Map.keys() |> Enum.max()

  @doc "Encodes the delta in librsync wire format. Zero-length commands are omitted."
  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{commands: commands}) do
    [<<@magic::32>>, Enum.map(commands, &encode_command/1), <<0>>]
  end

  defp encode_command({:literal, <<>>}), do: []
  defp encode_command({:copy, _offset, 0}), do: []

  defp encode_command({:literal, data}) do
    len = byte_size(data)

    if len <= @max_immediate do
      [Map.fetch!(@literal_immediate, len), data]
    else
      w = int_width(len)
      [<<Map.fetch!(@literal_by_width, w), len::size(w * 8)>>, data]
    end
  end

  defp encode_command({:copy, offset, len}) do
    w1 = int_width(offset)
    w2 = int_width(len)
    <<Map.fetch!(@copy_by_widths, {w1, w2}), offset::size(w1 * 8), len::size(w2 * 8)>>
  end

  # librsync rs_int_len
  defp int_width(v) when v <= 0xFF, do: 1
  defp int_width(v) when v <= 0xFFFF, do: 2
  defp int_width(v) when v <= 0xFFFFFFFF, do: 4
  defp int_width(v) when v <= 0xFFFFFFFFFFFFFFFF, do: 8

  @doc "Decodes a librsync delta."
  @spec decode(binary()) :: {:ok, t()} | {:error, decode_error()}
  def decode(<<@magic::32, body::binary>>), do: decode_commands(body, [])
  def decode(<<magic::32, _::binary>>), do: {:error, {:bad_magic, magic}}
  def decode(bin) when is_binary(bin), do: {:error, :truncated_header}

  for {op, kind, imm, w1, w2} <- @table do
    case kind do
      :end ->
        defp decode_commands(<<unquote(op)>>, acc),
          do: {:ok, %__MODULE__{commands: Enum.reverse(acc)}}

        defp decode_commands(<<unquote(op), _::binary>>, _acc), do: {:error, :trailing_data}

      :literal when imm > 0 ->
        defp decode_commands(<<unquote(op), data::binary-size(unquote(imm)), rest::binary>>, acc),
          do: decode_commands(rest, [{:literal, data} | acc])

      :literal ->
        defp decode_commands(<<unquote(op), len::size(unquote(w1 * 8)), rest::binary>>, acc)
             when byte_size(rest) >= len do
          <<data::binary-size(len), rest::binary>> = rest
          decode_commands(rest, [{:literal, data} | acc])
        end

      :copy ->
        defp decode_commands(
               <<unquote(op), offset::size(unquote(w1 * 8)), len::size(unquote(w2 * 8)),
                 rest::binary>>,
               acc
             ),
             do: decode_commands(rest, [{:copy, offset, len} | acc])

      :reserved ->
        defp decode_commands(<<unquote(op), _::binary>>, _acc),
          do: {:error, {:reserved_opcode, unquote(op)}}
    end
  end

  defp decode_commands(<<>>, _acc), do: {:error, :missing_end}
  defp decode_commands(_truncated_command, _acc), do: {:error, :truncated}

  # ---------------------------------------------------------------------------
  # Patch
  # ---------------------------------------------------------------------------

  @doc "Applies the delta to `basis`. See `Rexd.patch/2`."
  @spec apply_to(binary(), t()) ::
          {:ok, binary()} | {:error, {:copy_out_of_range, non_neg_integer(), non_neg_integer()}}
  def apply_to(basis, %__MODULE__{commands: commands}) when is_binary(basis) do
    apply_commands(commands, basis, byte_size(basis), [])
  end

  defp apply_commands([], _basis, _size, acc),
    do: {:ok, acc |> :lists.reverse() |> IO.iodata_to_binary()}

  defp apply_commands([{:literal, data} | rest], basis, size, acc),
    do: apply_commands(rest, basis, size, [data | acc])

  defp apply_commands([{:copy, offset, len} | rest], basis, size, acc)
       when offset + len <= size,
       do: apply_commands(rest, basis, size, [binary_part(basis, offset, len) | acc])

  defp apply_commands([{:copy, offset, len} | _], _basis, _size, _acc),
    do: {:error, {:copy_out_of_range, offset, len}}
end
