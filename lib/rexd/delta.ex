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

  `decode/1` rejects what librsync's patcher treats as a corrupt stream:
  zero-length literal or copy commands, and arguments of 2^63 or more
  (librsync reads them as signed 64-bit integers). Whether copies fit the
  basis is checked by `Rexd.patch/3`, the first point where the basis is
  known.
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
          | {:zero_length, :literal | :copy}
          | {:argument_too_large, non_neg_integer()}

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
  @max_argument 0x7FFFFFFFFFFFFFFF

  @doc "Encodes the delta in librsync wire format. Zero-length commands are omitted."
  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{commands: commands}),
    do: [encode_header(), encode_commands(commands), encode_end()]

  @doc false
  @spec encode_header() :: binary()
  def encode_header, do: <<@magic::32>>

  @doc false
  @spec encode_end() :: binary()
  def encode_end, do: <<0>>

  @doc false
  @spec encode_commands([command()]) :: iodata()
  def encode_commands(commands), do: Enum.map(commands, &encode_command/1)

  defp encode_command({:literal, <<>>}), do: []
  defp encode_command({:copy, _offset, 0}), do: []

  defp encode_command({:literal, data}) when byte_size(data) <= @max_immediate,
    do: [Map.fetch!(@literal_immediate, byte_size(data)), data]

  defp encode_command({:literal, data}) do
    len = byte_size(data)
    w = int_width(len)
    [<<Map.fetch!(@literal_by_width, w), len::size(w * 8)>>, data]
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

  defp decode_commands(body, acc), do: decode_step(next_command(body), acc)

  defp decode_step({:ok, :end, <<>>}, acc), do: {:ok, %__MODULE__{commands: Enum.reverse(acc)}}
  defp decode_step({:ok, :end, _rest}, _acc), do: {:error, :trailing_data}

  defp decode_step({:ok, {:copy, _offset, _len} = copy, rest}, acc),
    do: decode_commands(rest, [copy | acc])

  defp decode_step({:ok, {:literal_header, len}, rest}, acc) when byte_size(rest) >= len do
    <<data::binary-size(len), rest::binary>> = rest
    decode_commands(rest, [{:literal, data} | acc])
  end

  defp decode_step({:ok, {:literal_header, _len}, _rest}, _acc), do: {:error, :truncated}
  defp decode_step(:end_of_input, _acc), do: {:error, :missing_end}
  defp decode_step(:incomplete, _acc), do: {:error, :truncated}
  defp decode_step({:error, _reason} = error, _acc), do: error

  @doc false
  # Decodes the command at the start of `bytes`, without its literal data:
  #
  #   {:ok, :end, rest}
  #   {:ok, {:copy, offset, len}, rest}
  #   {:ok, {:literal_header, len}, rest}   - `len` bytes of data follow in rest
  #   :end_of_input                         - `bytes` is empty
  #   :incomplete                           - a command has started but is cut off
  #   {:error, reason}
  #
  # librsync reads arguments as signed 64-bit integers and rejects zero lengths
  # (patch.c), so such commands are reported as errors.
  @spec next_command(binary()) ::
          {:ok,
           :end | {:copy, non_neg_integer(), pos_integer()} | {:literal_header, pos_integer()},
           binary()}
          | :end_of_input
          | :incomplete
          | {:error, decode_error()}
  def next_command(bytes)

  for {op, :end, _imm, _w1, _w2} <- @table do
    def next_command(<<unquote(op), rest::binary>>), do: {:ok, :end, rest}
  end

  for {op, :literal, imm, 0, 0} <- @table, imm > 0 do
    def next_command(<<unquote(op), rest::binary>>),
      do: {:ok, {:literal_header, unquote(imm)}, rest}
  end

  for {op, :literal, 0, w, 0} <- @table do
    def next_command(<<unquote(op), 0::size(unquote(w * 8)), _::binary>>),
      do: {:error, {:zero_length, :literal}}

    def next_command(<<unquote(op), len::size(unquote(w * 8)), _::binary>>)
        when len > @max_argument,
        do: {:error, {:argument_too_large, len}}

    def next_command(<<unquote(op), len::size(unquote(w * 8)), rest::binary>>),
      do: {:ok, {:literal_header, len}, rest}
  end

  for {op, :copy, 0, w1, w2} <- @table do
    def next_command(
          <<unquote(op), _::size(unquote(w1 * 8)), 0::size(unquote(w2 * 8)), _::binary>>
        ),
        do: {:error, {:zero_length, :copy}}

    def next_command(
          <<unquote(op), offset::size(unquote(w1 * 8)), len::size(unquote(w2 * 8)), _::binary>>
        )
        when offset > @max_argument or len > @max_argument,
        do: {:error, {:argument_too_large, max(offset, len)}}

    def next_command(
          <<unquote(op), offset::size(unquote(w1 * 8)), len::size(unquote(w2 * 8)), rest::binary>>
        ),
        do: {:ok, {:copy, offset, len}, rest}
  end

  for {op, :reserved, _imm, _w1, _w2} <- @table do
    def next_command(<<unquote(op), _::binary>>), do: {:error, {:reserved_opcode, unquote(op)}}
  end

  def next_command(<<>>), do: :end_of_input
  def next_command(_cut_off), do: :incomplete
end
