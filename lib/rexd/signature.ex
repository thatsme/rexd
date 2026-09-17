defmodule Rexd.Signature do
  @moduledoc """
  A block signature of a basis binary, and its librsync wire encoding.

  The basis is split into `block_len`-byte blocks (the last one may be
  shorter). Each block contributes a `{weak, strong}` pair: its rolling
  checksum and the first `strong_sum_len` bytes of its strong hash.

  librsync defines four signature types, all supported:

  | `weak` | `strong` | magic | librsync name | `strong_sum_len` |
  |---|---|---|---|---|
  | `:rabinkarp` | `:blake2` | `0x72730147` | `RS_RK_BLAKE2_SIG_MAGIC` | 1..32 |
  | `:rabinkarp` | `:md4` | `0x72730146` | `RS_RK_MD4_SIG_MAGIC` | 1..16 |
  | `:rollsum` | `:blake2` | `0x72730137` | `RS_BLAKE2_SIG_MAGIC` | 1..32 |
  | `:rollsum` | `:md4` | `0x72730136` | `RS_MD4_SIG_MAGIC` | 1..16 |

  RabinKarp with BLAKE2b is the default and the default of librsync 2.3 and
  later. The rollsum and MD4 types exist for peers using older librsync
  defaults; MD4 is not collision-resistant.

  Wire format, all integers big-endian:

      u32 magic
      u32 block_len
      u32 strong_sum_len
      repeated: u32 weak, strong_sum_len bytes strong

  The format does not record the basis length, so a decoded signature cannot
  tell whether its last block is short.

  `index` maps each weak checksum to the strong hashes seen with it, and each
  of those to a block number. It is not part of the wire format;
  `build_index/1` fills it and `Rexd.delta/2` calls that when the index is
  missing. Building and querying it take constant time per block however the
  checksums are distributed, so a signature crafted to share one weak
  checksum across many blocks costs no more to process than any other.
  """

  alias Rexd.{Blake2b, MD4, RabinKarp, Rollsum}

  @magics %{
    {:rabinkarp, :blake2} => 0x72730147,
    {:rabinkarp, :md4} => 0x72730146,
    {:rollsum, :blake2} => 0x72730137,
    {:rollsum, :md4} => 0x72730136
  }
  @kinds Map.new(@magics, fn {kinds, magic} -> {magic, kinds} end)
  @max_strong_sum_len %{blake2: 32, md4: 16}
  @max_u32 0xFFFFFFFF
  @default_block_len 2048

  defstruct [
    :block_len,
    :strong_sum_len,
    weak: :rabinkarp,
    strong: :blake2,
    blocks: [],
    index: nil
  ]

  @typedoc "Rolling checksum algorithm."
  @type weak :: :rabinkarp | :rollsum

  @typedoc "Strong hash algorithm."
  @type strong :: :blake2 | :md4

  @typedoc "Weak checksum and truncated strong hash of one block."
  @type block :: {non_neg_integer(), binary()}

  @typedoc "Weak checksum to strong hash to the lowest block number carrying both."
  @type index :: %{non_neg_integer() => %{binary() => non_neg_integer()}}

  @type t :: %__MODULE__{
          block_len: pos_integer(),
          strong_sum_len: 1..32,
          weak: weak(),
          strong: strong(),
          blocks: [block()],
          index: index() | nil
        }

  @typedoc "Reasons `decode/1` can fail."
  @type decode_error ::
          :truncated_header
          | :truncated
          | {:bad_magic, non_neg_integer()}
          | {:invalid_block_len, non_neg_integer()}
          | {:invalid_strong_sum_len, non_neg_integer()}

  @doc """
  The librsync magic number of the signature's type.

      iex> Rexd.Signature.magic(Rexd.signature(""))
      0x72730147
  """
  @spec magic(t()) :: non_neg_integer()
  def magic(%__MODULE__{weak: weak, strong: strong}), do: Map.fetch!(@magics, {weak, strong})

  @doc false
  # Rexd.signature/2 delegates here.
  @spec compute(binary(), keyword()) :: t()
  def compute(basis, opts \\ []) when is_binary(basis) and is_list(opts) do
    sig = options!(opts)
    %{sig | blocks: compute_blocks(sig, basis, [])}
  end

  @doc false
  # Validates signature options, returning a signature with no blocks.
  @spec options!(keyword()) :: t()
  def options!(opts) when is_list(opts) do
    opts =
      Keyword.validate!(opts, [
        :strong_sum_len,
        block_len: @default_block_len,
        weak: :rabinkarp,
        strong: :blake2
      ])

    weak = valid_weak!(opts[:weak])
    strong = valid_strong!(opts[:strong])
    max_strong_sum_len = Map.fetch!(@max_strong_sum_len, strong)

    %__MODULE__{
      block_len: valid_block_len!(opts[:block_len]),
      strong_sum_len: valid_strong_sum_len!(opts[:strong_sum_len], max_strong_sum_len),
      weak: weak,
      strong: strong
    }
  end

  defp valid_weak!(weak) when weak in [:rabinkarp, :rollsum], do: weak

  defp valid_weak!(other),
    do: raise(ArgumentError, "weak must be :rabinkarp or :rollsum, got: #{inspect(other)}")

  defp valid_strong!(strong) when strong in [:blake2, :md4], do: strong

  defp valid_strong!(other),
    do: raise(ArgumentError, "strong must be :blake2 or :md4, got: #{inspect(other)}")

  defp valid_block_len!(len) when is_integer(len) and len in 1..@max_u32, do: len

  defp valid_block_len!(other),
    do:
      raise(
        ArgumentError,
        "block_len must be an integer in 1..#{@max_u32}, got: #{inspect(other)}"
      )

  defp valid_strong_sum_len!(nil, max), do: max
  defp valid_strong_sum_len!(len, max) when is_integer(len) and len in 1..max//1, do: len

  defp valid_strong_sum_len!(other, max),
    do:
      raise(
        ArgumentError,
        "strong_sum_len must be an integer in 1..#{max}, got: #{inspect(other)}"
      )

  defp compute_blocks(_sig, <<>>, acc), do: Enum.reverse(acc)

  defp compute_blocks(%__MODULE__{block_len: block_len} = sig, basis, acc)
       when byte_size(basis) >= block_len do
    <<block::binary-size(block_len), rest::binary>> = basis
    compute_blocks(sig, rest, [block_entry(sig, block) | acc])
  end

  # Shorter than block_len: the final block.
  defp compute_blocks(sig, last, acc), do: Enum.reverse([block_entry(sig, last) | acc])

  defp block_entry(sig, block),
    do: {weak_module(sig.weak).hash(block), strong(sig.strong, block, sig.strong_sum_len)}

  @doc false
  @spec weak_module(weak()) :: module()
  def weak_module(:rabinkarp), do: RabinKarp
  def weak_module(:rollsum), do: Rollsum

  @doc false
  # The strong hash of `data` with algorithm `kind`, truncated to
  # `strong_sum_len` bytes.
  @spec strong(strong(), binary(), pos_integer()) :: binary()
  def strong(kind, data, strong_sum_len) do
    <<sum::binary-size(strong_sum_len), _::binary>> = full_strong(kind, data)
    sum
  end

  defp full_strong(:blake2, data), do: Blake2b.hash(data)
  defp full_strong(:md4, data), do: MD4.hash(data)

  @doc "Encodes the signature in librsync wire format."
  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{} = sig), do: [encode_header(sig) | encode_blocks(sig)]

  @doc false
  @spec encode_header(t()) :: binary()
  def encode_header(%__MODULE__{block_len: block_len, strong_sum_len: strong_sum_len} = sig),
    do: <<magic(sig)::32, block_len::32, strong_sum_len::32>>

  @doc false
  @spec encode_blocks(t()) :: [binary()]
  def encode_blocks(%__MODULE__{blocks: blocks}),
    do: Enum.map(blocks, fn {weak, strong} -> <<weak::32, strong::binary>> end)

  @doc "Decodes a librsync signature of any of the four types."
  @spec decode(binary()) :: {:ok, t()} | {:error, decode_error()}
  def decode(<<magic::32, block_len::32, strong_sum_len::32, body::binary>>)
      when is_map_key(@kinds, magic),
      do: decode_body(Map.fetch!(@kinds, magic), block_len, strong_sum_len, body)

  def decode(<<magic::32, _::binary>>) when is_map_key(@kinds, magic),
    do: {:error, :truncated_header}

  def decode(<<magic::32, _::binary>>), do: {:error, {:bad_magic, magic}}
  def decode(bin) when is_binary(bin), do: {:error, :truncated_header}

  defp decode_body(_kinds, 0, _strong_sum_len, _body), do: {:error, {:invalid_block_len, 0}}

  defp decode_body({_weak, strong}, _block_len, strong_sum_len, _body)
       when strong_sum_len < 1 or strong_sum_len > :erlang.map_get(strong, @max_strong_sum_len),
       do: {:error, {:invalid_strong_sum_len, strong_sum_len}}

  defp decode_body({weak, strong}, block_len, strong_sum_len, body)
       when rem(byte_size(body), 4 + strong_sum_len) == 0 do
    blocks = for <<sum::32, hash::binary-size(strong_sum_len) <- body>>, do: {sum, hash}

    {:ok,
     %__MODULE__{
       block_len: block_len,
       strong_sum_len: strong_sum_len,
       weak: weak,
       strong: strong,
       blocks: blocks
     }}
  end

  defp decode_body(_kinds, _block_len, _strong_sum_len, _body), do: {:error, :truncated}

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
      |> Enum.reduce(%{}, fn {{weak, strong}, block_no}, index ->
        Map.update(index, weak, %{strong => block_no}, &Map.put_new(&1, strong, block_no))
      end)

    %{sig | index: index}
  end
end
