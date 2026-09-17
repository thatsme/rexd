defmodule Rexd.MD4 do
  @moduledoc false
  # MD4 (RFC 1320), the strong hash of librsync's `RS_MD4_SIG_MAGIC` and
  # `RS_RK_MD4_SIG_MAGIC` signatures.
  #
  # MD4 is broken as a cryptographic hash and is provided only to read and write
  # those signature types. OTP's `:crypto` offers MD4 only when OpenSSL's legacy
  # provider is available, so it is implemented here.

  import Bitwise

  @mask 0xFFFFFFFF

  # {round, message word, shift} for the 48 steps of RFC 1320 section 3.4.
  @steps List.flatten([
           for(_ <- 1..4, {k, s} <- Enum.zip(0..3, [3, 7, 11, 19]), do: {1, k, s})
           |> Enum.with_index()
           |> Enum.map(fn {{r, _k, s}, i} -> {r, i, s} end),
           for(
             {k, i} <- Enum.with_index([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]),
             do: {2, k, Enum.at([3, 5, 9, 13], rem(i, 4))}
           ),
           for(
             {k, i} <- Enum.with_index([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]),
             do: {3, k, Enum.at([3, 9, 11, 15], rem(i, 4))}
           )
         ])

  @doc "Returns the 16-byte MD4 digest of `data`."
  @spec hash(binary()) :: <<_::128>>
  def hash(data) when is_binary(data) do
    {a, b, c, d} = blocks(data, {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}, byte_size(data))
    <<a::little-32, b::little-32, c::little-32, d::little-32>>
  end

  defp blocks(<<block::binary-size(64), rest::binary>>, state, size),
    do: blocks(rest, compress(state, block), size)

  # Final bytes, the 0x80 marker, zero padding to 56 mod 64, and the bit length.
  defp blocks(tail, state, size) do
    padding = (55 - rem(byte_size(tail), 64)) |> Integer.mod(64)

    last =
      <<tail::binary, 0x80, 0::size(padding * 8), size * 8 &&& 0xFFFFFFFFFFFFFFFF::little-64>>

    for <<block::binary-size(64) <- last>>, reduce: state, do: (state -> compress(state, block))
  end

  defp compress({a, b, c, d} = state, block) do
    words = List.to_tuple(for <<word::little-32 <- block>>, do: word)
    {a2, b2, c2, d2} = Enum.reduce(@steps, state, &step(&1, &2, words))
    {a + a2 &&& @mask, b + b2 &&& @mask, c + c2 &&& @mask, d + d2 &&& @mask}
  end

  # Each step updates the first word of the state and rotates the roles, so
  # the next step sees {d, a', b, c}.
  defp step({round, k, shift}, {a, b, c, d}, words) do
    sum = a + mix(round, b, c, d) + elem(words, k) + constant(round) &&& @mask
    {d, rotl(sum, shift), b, c}
  end

  defp mix(1, b, c, d), do: (b &&& c) ||| (bnot(b) &&& d)
  defp mix(2, b, c, d), do: (b &&& c) ||| (b &&& d) ||| (c &&& d)
  defp mix(3, b, c, d), do: bxor(b, bxor(c, d))

  defp constant(1), do: 0
  defp constant(2), do: 0x5A827999
  defp constant(3), do: 0x6ED9EBA1

  defp rotl(x, n), do: (x <<< n ||| x >>> (32 - n)) &&& @mask
end
