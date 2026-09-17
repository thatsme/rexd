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

  # ---------------------------------------------------------------------------
  # compress/2 is generated at compile time from @steps: each of the 48 steps
  # becomes a rebinding of one state variable, with the message words bound
  # once from the block. The direct form (a tuple per step, folded with
  # Enum.reduce) allocates on every step, which made its speed depend on the
  # caller's heap state by 2-3x; see NOTES.md, "Code shaped by performance".
  # ---------------------------------------------------------------------------

  var = fn name -> Macro.var(name, __MODULE__) end
  words = for i <- 0..15, do: var.(:"x#{i}")
  [a, b, c, d] = for name <- [:a, :b, :c, :d], do: var.(name)
  mask = @mask

  # Step j updates a, d, c, b in turn; the other three are its operands in
  # the order RFC 1320 lists them.
  roles = [{a, b, c, d}, {d, a, b, c}, {c, d, a, b}, {b, c, d, a}]

  mix = fn
    1, x, y, z ->
      quote(do: (unquote(x) &&& unquote(y)) ||| (bnot(unquote(x)) &&& unquote(z)))

    2, x, y, z ->
      quote(
        do:
          (unquote(x) &&& unquote(y)) ||| (unquote(x) &&& unquote(z)) |||
            (unquote(y) &&& unquote(z))
      )

    3, x, y, z ->
      quote(do: bxor(unquote(x), bxor(unquote(y), unquote(z))))
  end

  constant = %{1 => 0, 2 => 0x5A827999, 3 => 0x6ED9EBA1}

  steps =
    for {{round, k, shift}, j} <- Enum.with_index(@steps) do
      {target, x, y, z} = Enum.at(roles, rem(j, 4))

      quote do
        t =
          unquote(target) + unquote(mix.(round, x, y, z)) + unquote(Enum.at(words, k)) +
            unquote(constant[round]) &&& unquote(mask)

        unquote(target) = (t <<< unquote(shift) ||| t >>> unquote(32 - shift)) &&& unquote(mask)
      end
    end

  block_pattern = for w <- words, do: quote(do: unquote(w) :: little - 32)
  initial = for v <- [a, b, c, d], do: var.(:"#{elem(v, 0)}0")

  defp compress({unquote_splicing(initial)}, <<unquote_splicing(block_pattern)>>) do
    unquote_splicing(
      for {v, v0} <- Enum.zip([a, b, c, d], initial), do: quote(do: unquote(v) = unquote(v0))
    )

    unquote_splicing(steps)

    {unquote_splicing(
       for {v, v0} <- Enum.zip([a, b, c, d], initial),
           do: quote(do: unquote(v0) + unquote(v) &&& unquote(mask))
     )}
  end
end
