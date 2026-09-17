defmodule Rexd.LegacySignatureTest do
  # The rollsum and MD4 signature types of older librsync defaults.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Rexd.{Delta, MD4, Rollsum, Signature}
  alias Rexd.Test.Oracle

  doctest Rollsum
  doctest MD4

  @kinds [{:rabinkarp, :blake2}, {:rabinkarp, :md4}, {:rollsum, :blake2}, {:rollsum, :md4}]

  defp kinds, do: member_of(@kinds)

  defp opts({weak, strong}, block_len, strong_sum_len),
    do: [weak: weak, strong: strong, block_len: block_len, strong_sum_len: strong_sum_len]

  defp encode(sig), do: sig |> Signature.encode() |> IO.iodata_to_binary()

  describe "Rexd.Rollsum" do
    test "matches the librsync weak sum for a known block" do
      # rdiff -R rollsum -H md4 -b 16 over the first 16 bytes of this input
      assert Rollsum.hash(binary_part("hello world, this is rexd", 0, 16)) == 0x443507DD
    end

    property "rolling equals from-scratch at every offset" do
      check all n <- integer(1..300), data <- binary(min_length: n, max_length: n + 300) do
        {count, unused} = Rollsum.window(n)
        last = byte_size(data) - n

        Enum.reduce(0..last, Rollsum.hash(binary_part(data, 0, n)), fn pos, sum ->
          assert sum == Rollsum.hash(binary_part(data, pos, n))
          roll(sum, data, pos, last, n, count, unused)
        end)
      end
    end

    property "shrinking the window equals hashing the suffix" do
      check all data <- binary(min_length: 1, max_length: 300) do
        n = byte_size(data)

        Enum.reduce(0..(n - 1), Rollsum.hash(data), fn pos, sum ->
          {count, unused} = Rollsum.window(n - pos - 1)
          sum = Rollsum.rollout(sum, :binary.at(data, pos), count, unused)
          assert sum == Rollsum.hash(binary_part(data, pos + 1, n - pos - 1))
          sum
        end)
      end
    end

    test "window lengths past 2^16 wrap like librsync's 16-bit count" do
      data = :crypto.strong_rand_bytes(70_000)
      {count, unused} = Rollsum.window(66_000)
      sum = Rollsum.hash(binary_part(data, 0, 66_000))
      rolled = Rollsum.rotate(sum, :binary.at(data, 0), :binary.at(data, 66_000), count, unused)
      assert rolled == Rollsum.hash(binary_part(data, 1, 66_000))
    end
  end

  defp roll(sum, _data, last, last, _n, _count, _unused), do: sum

  defp roll(sum, data, pos, _last, n, count, unused),
    do: Rollsum.rotate(sum, :binary.at(data, pos), :binary.at(data, pos + n), count, unused)

  describe "Rexd.MD4" do
    test "RFC 1320 test suite" do
      vectors = [
        {"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
        {"a", "bde52cb31de33e46245e05fbdbd6fb24"},
        {"abc", "a448017aaf21d8525fc10ae87aa6729d"},
        {"message digest", "d9130a8164549fe818874806e1c7014b"},
        {"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "043f8582f241db351ce627e153e7f0e4"},
        {String.duplicate("1234567890", 8), "e33b4ddc9c38f2199c3e7b164fcc0536"}
      ]

      for {input, digest} <- vectors do
        assert MD4.hash(input) |> Base.encode16(case: :lower) == digest, inspect(input)
      end
    end

    property "matches :crypto where the runtime provides MD4" do
      check all data <- binary(max_length: 600) do
        assert MD4.hash(data) == crypto_md4(data)
      end
    end
  end

  defp crypto_md4(data) do
    :crypto.hash(:md4, data)
  rescue
    _unavailable -> MD4.hash(data)
  end

  describe "signatures" do
    test "defaults and limits follow the strong hash" do
      assert Rexd.signature("abc", strong: :md4).strong_sum_len == 16
      assert Rexd.signature("abc", strong: :blake2).strong_sum_len == 32

      assert_raise ArgumentError, fn ->
        Rexd.signature("abc", strong: :md4, strong_sum_len: 17)
      end

      assert_raise ArgumentError, fn -> Rexd.signature("abc", weak: :adler) end
      assert_raise ArgumentError, fn -> Rexd.signature("abc", strong: :sha1) end
    end

    test "each type encodes its librsync magic" do
      magics =
        for {weak, strong} <- @kinds,
            do:
              "abc" |> Rexd.signature(weak: weak, strong: strong) |> encode() |> binary_part(0, 4)

      assert magics == [
               <<0x72730147::32>>,
               <<0x72730146::32>>,
               <<0x72730137::32>>,
               <<0x72730136::32>>
             ]
    end

    property "encode/decode round-trips every type" do
      check all basis <- binary(max_length: 500), kinds <- kinds(), block_len <- integer(1..64) do
        sig = Rexd.signature(basis, opts(kinds, block_len, 16))
        assert Signature.decode(encode(sig)) == {:ok, sig}
      end
    end

    property "delta and patch round-trip with every type" do
      check all basis <- binary(max_length: 3000),
                insert <- binary(max_length: 200),
                cut <- integer(0..3000),
                kinds <- kinds(),
                block_len <- member_of([1, 7, 64, 256]) do
        cut = rem(cut, byte_size(basis) + 1)
        <<a::binary-size(cut), b::binary>> = basis
        new = b <> insert <> a
        sig = Rexd.signature(basis, opts(kinds, block_len, 8))

        assert Rexd.patch(basis, Rexd.delta(sig, new)) == {:ok, new}
        streamed = sig |> Rexd.Stream.delta([new]) |> Enum.join()
        assert streamed == Rexd.delta(sig, new) |> Delta.encode() |> IO.iodata_to_binary()
      end
    end

    property "streamed signatures equal whole-binary ones for every type" do
      check all basis <- binary(max_length: 5000), kinds <- kinds(), size <- integer(1..700) do
        opts = opts(kinds, 64, 12)
        chunks = for <<chunk::binary-size(size) <- basis>>, do: chunk

        chunks =
          chunks ++
            [binary_part(basis, length(chunks) * size, byte_size(basis) - length(chunks) * size)]

        assert chunks |> Rexd.Stream.signature(opts) |> Enum.join() ==
                 encode(Rexd.signature(basis, opts))
      end
    end
  end

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    property "signatures equal rdiff's for every type", %{tmp_dir: dir} do
      check all basis <- binary(max_length: 4000),
                kinds <- kinds(),
                block_len <- member_of([1, 16, 100, 2048]),
                strong_sum_len <- member_of([1, 8, 16]),
                max_runs: 60 do
        theirs = Oracle.rdiff_signature(basis, block_len, strong_sum_len, dir, kinds)
        ours = Rexd.signature(basis, opts(kinds, block_len, strong_sum_len))
        assert encode(ours) == theirs
        assert Signature.decode(theirs) == {:ok, ours}
      end
    end

    property "deltas interoperate with rdiff for every type", %{tmp_dir: dir} do
      check all basis <- binary(max_length: 4000),
                insert <- binary(max_length: 300),
                cut <- integer(0..4000),
                kinds <- kinds(),
                block_len <- member_of([4, 64, 512]),
                max_runs: 40 do
        cut = rem(cut, byte_size(basis) + 1)
        <<a::binary-size(cut), b::binary>> = basis
        new = b <> insert <> a
        sig = Rexd.signature(basis, opts(kinds, block_len, 16))

        {:ok, theirs} = sig |> encode() |> Oracle.rdiff_delta(new, dir) |> Delta.decode()
        assert Rexd.patch(basis, theirs) == {:ok, new}

        ours = sig |> Rexd.delta(new) |> Delta.encode() |> IO.iodata_to_binary()
        assert Oracle.rdiff_patch(basis, ours, dir) == new
      end
    end
  end
end
