defmodule Rexd.Signature do
  @moduledoc """
  A block signature of a basis binary, and its librsync wire encoding.

  The basis is split into `block_len`-byte blocks (the last one may be
  shorter). Each block contributes a `{weak, strong}` pair: the RabinKarp
  checksum of the block and the first `strong_sum_len` bytes of its
  BLAKE2b-256 digest.

  Wire format (`RS_RK_BLAKE2_SIG_MAGIC`), all integers big-endian:

      u32 magic = 0x72730147
      u32 block_len
      u32 strong_sum_len
      repeated: u32 weak, strong_sum_len bytes strong

  The format does not record the basis length, so a decoded signature cannot
  tell whether its last block is short.

  `index` maps each weak checksum to the blocks carrying it. It is not part
  of the wire format; `build_index/1` fills it and `Rexd.delta/2` calls that
  when the index is missing.
  """

  alias Rexd.{Blake2b, RabinKarp}

  @magic 0x72730147
  @max_strong_sum_len 32
  @max_u32 0xFFFFFFFF

  @unsupported_magics %{
    0x72730136 => :md4,
    0x72730137 => :rollsum_blake2,
    0x72730146 => :rabinkarp_md4
  }

  @default_block_len 2048

  defstruct [:block_len, :strong_sum_len, blocks: [], index: nil]

  @typedoc "Weak checksum and truncated strong hash of one block."
  @type block :: {RabinKarp.t(), binary()}

  @typedoc "Weak checksum to `{block_no, strong}` pairs, in ascending block order."
  @type index :: %{RabinKarp.t() => [{non_neg_integer(), binary()}]}

  @type t :: %__MODULE__{
          block_len: pos_integer(),
          strong_sum_len: 1..32,
          blocks: [block()],
          index: index() | nil
        }

  @typedoc "Reasons `decode/1` can fail."
  @type decode_error ::
          :truncated_header
          | :truncated
          | {:bad_magic, non_neg_integer()}
          | {:unsupported_magic, atom()}
          | {:invalid_block_len, non_neg_integer()}
          | {:invalid_strong_sum_len, non_neg_integer()}

  @doc "The signature magic number this library reads and writes."
  @spec magic() :: non_neg_integer()
  def magic, do: @magic

  @doc """
  Computes the signature of `basis`. See `Rexd.signature/2` for options.

  Raises `ArgumentError` on invalid options.
  """
  @spec compute(binary(), keyword()) :: t()
  def compute(basis, opts \\ []) when is_binary(basis) and is_list(opts) do
    opts = Keyword.validate!(opts, block_len: @default_block_len, strong_sum_len: 32)
    block_len = valid_block_len!(opts[:block_len])
    strong_sum_len = valid_strong_sum_len!(opts[:strong_sum_len])

    %__MODULE__{
      block_len: block_len,
      strong_sum_len: strong_sum_len,
      blocks: compute_blocks(block_len, strong_sum_len, basis, [])
    }
  end

  defp valid_block_len!(len) when is_integer(len) and len in 1..@max_u32, do: len

  defp valid_block_len!(other),
    do:
      raise(
        ArgumentError,
        "block_len must be an integer in 1..#{@max_u32}, got: #{inspect(other)}"
      )

  defp valid_strong_sum_len!(len) when is_integer(len) and len in 1..@max_strong_sum_len, do: len

  defp valid_strong_sum_len!(other) do
    raise ArgumentError,
          "strong_sum_len must be an integer in 1..#{@max_strong_sum_len}, got: #{inspect(other)}"
  end

  defp compute_blocks(_block_len, _strong_sum_len, <<>>, acc), do: Enum.reverse(acc)

  defp compute_blocks(block_len, strong_sum_len, basis, acc) when byte_size(basis) >= block_len do
    <<block::binary-size(block_len), rest::binary>> = basis
    compute_blocks(block_len, strong_sum_len, rest, [block_entry(block, strong_sum_len) | acc])
  end

  # Shorter than block_len: the final block.
  defp compute_blocks(_block_len, strong_sum_len, last, acc),
    do: Enum.reverse([block_entry(last, strong_sum_len) | acc])

  defp block_entry(block, strong_sum_len),
    do: {RabinKarp.hash(block), strong(block, strong_sum_len)}

  @doc "The strong hash of `data` truncated to `strong_sum_len` bytes."
  @spec strong(binary(), 1..32) :: binary()
  def strong(data, strong_sum_len) do
    <<s::binary-size(strong_sum_len), _::binary>> = Blake2b.hash(data)
    s
  end

  @doc "Encodes the signature in librsync wire format."
  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{block_len: block_len, strong_sum_len: strong_sum_len, blocks: blocks}) do
    [
      <<@magic::32, block_len::32, strong_sum_len::32>>
      | Enum.map(blocks, fn {weak, strong} -> <<weak::32, strong::binary>> end)
    ]
  end

  @doc """
  Decodes a librsync signature.

  Only `RS_RK_BLAKE2_SIG_MAGIC` signatures are accepted; the MD4 and rollsum
  variants return `{:error, {:unsupported_magic, kind}}`.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, decode_error()}
  def decode(<<@magic::32, 0::32, _strong_sum_len::32, _::binary>>),
    do: {:error, {:invalid_block_len, 0}}

  def decode(<<@magic::32, _block_len::32, strong_sum_len::32, _::binary>>)
      when strong_sum_len not in 1..@max_strong_sum_len,
      do: {:error, {:invalid_strong_sum_len, strong_sum_len}}

  def decode(<<@magic::32, block_len::32, strong_sum_len::32, body::binary>>)
      when rem(byte_size(body), 4 + strong_sum_len) == 0 do
    blocks = for <<weak::32, strong::binary-size(strong_sum_len) <- body>>, do: {weak, strong}
    {:ok, %__MODULE__{block_len: block_len, strong_sum_len: strong_sum_len, blocks: blocks}}
  end

  def decode(<<@magic::32, _block_len::32, _strong_sum_len::32, _::binary>>),
    do: {:error, :truncated}

  def decode(<<@magic::32, _::binary>>), do: {:error, :truncated_header}

  def decode(<<magic::32, _::binary>>) when is_map_key(@unsupported_magics, magic),
    do: {:error, {:unsupported_magic, Map.fetch!(@unsupported_magics, magic)}}

  def decode(<<magic::32, _::binary>>), do: {:error, {:bad_magic, magic}}

  def decode(bin) when is_binary(bin), do: {:error, :truncated_header}

  @doc """
  Fills `index`, unless already present.

  Blocks that share both weak and strong checksum are stored once, under the
  lowest block number.
  """
  @spec build_index(t()) :: t()
  def build_index(%__MODULE__{index: index} = sig) when is_map(index), do: sig

  def build_index(%__MODULE__{blocks: blocks} = sig) do
    index =
      blocks
      |> Enum.with_index()
      |> Enum.reduce(%{}, fn {{weak, strong}, block_no}, acc ->
        Map.update(acc, weak, [{block_no, strong}], &add_candidate(&1, block_no, strong))
      end)
      |> Map.new(fn {weak, candidates} -> {weak, Enum.reverse(candidates)} end)

    %{sig | index: index}
  end

  # Candidates are accumulated newest-first; a strong hash already present
  # belongs to a lower-numbered block and wins.
  defp add_candidate(candidates, block_no, strong) do
    case List.keyfind(candidates, strong, 1) do
      nil -> [{block_no, strong} | candidates]
      _lower_block -> candidates
    end
  end
end
