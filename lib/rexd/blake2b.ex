defmodule Rexd.Blake2b do
  @moduledoc """
  BLAKE2b-256 (RFC 7693, unkeyed, digest length 32), the strong hash of
  librsync `RS_*_BLAKE2_SIG_MAGIC` signatures.

  librsync initialises BLAKE2b with a 32-byte digest length and truncates the
  result to the signature's `strong_sum_len`. BLAKE2b-256 is not a prefix of
  BLAKE2b-512: the digest length is part of the parameter block mixed into
  the initial state. `:crypto` only provides BLAKE2b-512, hence this module.

  Every 64-bit word is carried as two 32-bit halves (`hi`, `lo`) so that
  additions, XORs and rotations stay within the BEAM small-integer range and
  never allocate. The twelve rounds of the compression function are unrolled
  at compile time into a single function body of plain variable bindings.
  """

  import Bitwise

  @m32 0xFFFFFFFF
  @digest_len 32

  @iv [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179
  ]

  @sigma [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
  ]

  # Parameter block word 0: digest length 32, key length 0, fanout 1, depth 1.
  @h0 [hd(@iv) |> bxor(0x01010000 ||| @digest_len) | tl(@iv)]
  @h0_split @h0 |> Enum.flat_map(&[&1 >>> 32, &1 &&& @m32]) |> List.to_tuple()

  @doc """
  Returns the 32-byte BLAKE2b-256 digest of `data`.

      iex> Rexd.Blake2b.hash("abc") |> Base.encode16(case: :lower)
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
  """
  @spec hash(binary()) :: <<_::256>>
  def hash(data) when is_binary(data) do
    h = blocks(@h0_split, data, 0)
    <<digest::binary-size(@digest_len), _::binary>> = serialize(h)
    digest
  end

  defp serialize({h0, l0, h1, l1, h2, l2, h3, l3, h4, l4, h5, l5, h6, l6, h7, l7}) do
    <<l0::little-32, h0::little-32, l1::little-32, h1::little-32, l2::little-32, h2::little-32,
      l3::little-32, h3::little-32, l4::little-32, h4::little-32, l5::little-32, h5::little-32,
      l6::little-32, h6::little-32, l7::little-32, h7::little-32>>
  end

  # All blocks but the last are compressed with the "last block" flag clear.
  # The final block (possibly empty, zero-padded) sets it.
  defp blocks(h, <<block::binary-size(128), rest::binary>>, t) when rest != <<>> do
    blocks(compress(h, block, t + 128, 0), rest, t + 128)
  end

  defp blocks(h, last, t) do
    n = byte_size(last)
    compress(h, <<last::binary, 0::size((128 - n) * 8)>>, t + n, @m32)
  end

  # ---------------------------------------------------------------------------
  # Compile-time generation of compress/4.
  #
  # Each 64-bit quantity x is a pair of variables {xh, xl}. The generated body
  # is a flat sequence of bindings; variables are rebound as the rounds run.
  # ---------------------------------------------------------------------------

  var = fn name -> Macro.var(name, __MODULE__) end
  h_vars = for i <- 0..7, do: {var.(:"hh#{i}"), var.(:"hl#{i}")}
  m_vars = for i <- 0..15, do: {var.(:"mh#{i}"), var.(:"ml#{i}")}
  v_vars = for i <- 0..15, do: {var.(:"vh#{i}"), var.(:"vl#{i}")}
  t_var = var.(:t)
  f_var = var.(:f)

  # a = a + b + x  (mod 2^64)
  add3 = fn {ah, al}, {bh, bl}, {xh, xl} ->
    quote do
      lo = unquote(al) + unquote(bl) + unquote(xl)
      unquote(ah) = unquote(ah) + unquote(bh) + unquote(xh) + (lo >>> 32) &&& @m32
      unquote(al) = lo &&& @m32
    end
  end

  # a = a + b  (mod 2^64)
  add2 = fn {ah, al}, {bh, bl} ->
    quote do
      lo = unquote(al) + unquote(bl)
      unquote(ah) = unquote(ah) + unquote(bh) + (lo >>> 32) &&& @m32
      unquote(al) = lo &&& @m32
    end
  end

  # x = rotr64(x ^ y, n) for n in {16, 24, 32, 63}
  xor_rotr = fn {xh, xl}, {yh, yl}, n ->
    case n do
      32 ->
        quote do
          th = bxor(unquote(xh), unquote(yh))
          unquote(xh) = bxor(unquote(xl), unquote(yl))
          unquote(xl) = th
        end

      63 ->
        quote do
          th = bxor(unquote(xh), unquote(yh))
          tl = bxor(unquote(xl), unquote(yl))
          unquote(xh) = (th <<< 1 ||| tl >>> 31) &&& @m32
          unquote(xl) = (tl <<< 1 ||| th >>> 31) &&& @m32
        end

      n when n < 32 ->
        quote do
          th = bxor(unquote(xh), unquote(yh))
          tl = bxor(unquote(xl), unquote(yl))
          unquote(xh) = (th >>> unquote(n) ||| tl <<< unquote(32 - n)) &&& @m32
          unquote(xl) = (tl >>> unquote(n) ||| th <<< unquote(32 - n)) &&& @m32
        end
    end
  end

  # The G mixing function (RFC 7693 §3.1).
  mix = fn [a, b, c, d], x, y ->
    [
      add3.(a, b, x),
      xor_rotr.(d, a, 32),
      add2.(c, d),
      xor_rotr.(b, c, 24),
      add3.(a, b, y),
      xor_rotr.(d, a, 16),
      add2.(c, d),
      xor_rotr.(b, c, 63)
    ]
  end

  columns_then_diagonals = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14]
  ]

  rounds =
    for s <- @sigma,
        {quad, k} <- Enum.with_index(columns_then_diagonals),
        stmt <-
          mix.(
            Enum.map(quad, &Enum.at(v_vars, &1)),
            Enum.at(m_vars, Enum.at(s, 2 * k)),
            Enum.at(m_vars, Enum.at(s, 2 * k + 1))
          ) do
      stmt
    end

  # v[0..7] = h, v[8..15] = IV; v12 ^= t (low 64 bits), v14 ^= f.
  # Inputs never reach 2^64 bytes, so the high counter word v13 is unchanged.
  init =
    for i <- 0..15 do
      {vh, vl} = Enum.at(v_vars, i)

      {rh, rl} =
        if i < 8 do
          Enum.at(h_vars, i)
        else
          iv = Enum.at(@iv, i - 8)
          {iv >>> 32, iv &&& @m32}
        end

      {rh, rl} =
        case i do
          12 ->
            {quote(do: bxor(unquote(rh), unquote(t_var) >>> 32 &&& @m32)),
             quote(do: bxor(unquote(rl), unquote(t_var) &&& @m32))}

          14 ->
            {quote(do: bxor(unquote(rh), unquote(f_var))),
             quote(do: bxor(unquote(rl), unquote(f_var)))}

          _ ->
            {rh, rl}
        end

      quote do
        unquote(vh) = unquote(rh)
        unquote(vl) = unquote(rl)
      end
    end

  # h[i] ^= v[i] ^ v[i + 8]
  finalize =
    for i <- 0..7, half <- [0, 1] do
      h = elem(Enum.at(h_vars, i), half)
      a = elem(Enum.at(v_vars, i), half)
      b = elem(Enum.at(v_vars, i + 8), half)
      quote(do: bxor(unquote(h), bxor(unquote(a), unquote(b))))
    end

  state_pattern = for {h, l} <- h_vars, x <- [h, l], do: x

  # Message words are little-endian 64-bit: low half first.
  block_pattern =
    for {h, l} <- m_vars,
        x <- [quote(do: unquote(l) :: little - 32), quote(do: unquote(h) :: little - 32)],
        do: x

  defp compress(
         {unquote_splicing(state_pattern)},
         <<unquote_splicing(block_pattern)>>,
         unquote(t_var),
         unquote(f_var)
       ) do
    unquote_splicing(init)
    unquote_splicing(rounds)
    {unquote_splicing(finalize)}
  end
end
