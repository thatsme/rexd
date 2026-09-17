defmodule Rexd.SignatureTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.{Blake2b, RabinKarp, Signature}
  alias Rexd.Test.{Oracle, Vectors}

  doctest Rexd

  describe "compute/2" do
    test "one entry per block, last block short" do
      sig = Rexd.signature("abcdefghij", block_len: 4, strong_sum_len: 8)
      assert sig.block_len == 4
      assert sig.strong_sum_len == 8

      assert sig.blocks == [
               {RabinKarp.hash("abcd"), binary_part(Blake2b.hash("abcd"), 0, 8)},
               {RabinKarp.hash("efgh"), binary_part(Blake2b.hash("efgh"), 0, 8)},
               {RabinKarp.hash("ij"), binary_part(Blake2b.hash("ij"), 0, 8)}
             ]
    end

    test "edge cases" do
      assert Rexd.signature("").blocks == []
      assert length(Rexd.signature("abc", block_len: 2048).blocks) == 1
      assert length(Rexd.signature(:binary.copy("x", 64), block_len: 16).blocks) == 4
    end

    test "defaults" do
      sig = Rexd.signature("abc")
      assert {sig.block_len, sig.strong_sum_len} == {2048, 32}
    end

    test "raises on invalid options" do
      assert_raise ArgumentError, fn -> Rexd.signature("a", block_len: 0) end
      assert_raise ArgumentError, fn -> Rexd.signature("a", block_len: 1 <<< 32) end
      assert_raise ArgumentError, fn -> Rexd.signature("a", strong_sum_len: 0) end
      assert_raise ArgumentError, fn -> Rexd.signature("a", strong_sum_len: 33) end
      assert_raise ArgumentError, fn -> Rexd.signature("a", bogus: 1) end
    end

    property "deterministic encoding" do
      check all basis <- binary(), block_len <- integer(1..64) do
        a = IO.iodata_to_binary(Signature.encode(Rexd.signature(basis, block_len: block_len)))
        b = IO.iodata_to_binary(Signature.encode(Rexd.signature(basis, block_len: block_len)))
        assert a == b
      end
    end
  end

  describe "encode/decode" do
    property "round-trip" do
      check all basis <- binary(max_length: 500),
                block_len <- integer(1..64),
                strong_sum_len <- integer(1..32) do
        sig = Rexd.signature(basis, block_len: block_len, strong_sum_len: strong_sum_len)

        assert {:ok, ^sig} =
                 sig |> Signature.encode() |> IO.iodata_to_binary() |> Signature.decode()
      end
    end

    test "errors" do
      header = <<0x72730147::32, 16::32, 8::32>>
      assert Signature.decode(<<>>) == {:error, :truncated_header}
      assert Signature.decode(<<0x72730147::32, 16::32>>) == {:error, :truncated_header}
      assert Signature.decode(header <> <<1, 2, 3>>) == {:error, :truncated}

      assert Signature.decode(<<0x72730147::32, 0::32, 8::32>>) ==
               {:error, {:invalid_block_len, 0}}

      assert Signature.decode(<<0x72730147::32, 16::32, 33::32>>) ==
               {:error, {:invalid_strong_sum_len, 33}}

      assert Signature.decode(<<0x72730147::32, 16::32, 0::32>>) ==
               {:error, {:invalid_strong_sum_len, 0}}

      assert Signature.decode(<<0x72730136::32, 16::32, 8::32>>) ==
               {:error, {:unsupported_magic, :md4}}

      assert Signature.decode(<<0x72730236::32>>) == {:error, {:bad_magic, 0x72730236}}
    end
  end

  describe "build_index/1" do
    test "groups by weak, dedupes identical blocks under the lowest block number" do
      sig =
        Rexd.signature(:binary.copy("abcd", 3) <> "wxyz", block_len: 4) |> Signature.build_index()

      assert sig.index[RabinKarp.hash("abcd")] == %{Signature.strong("abcd", 32) => 0}
      assert sig.index[RabinKarp.hash("wxyz")] == %{Signature.strong("wxyz", 32) => 3}
      assert map_size(sig.index) == 2
    end
  end

  describe "committed rdiff vectors" do
    test "our signature equals rdiff's, byte for byte" do
      for v <- Vectors.signatures() do
        ours = Rexd.signature(v.basis, block_len: v.block_len, strong_sum_len: v.strong_sum_len)
        assert IO.iodata_to_binary(Signature.encode(ours)) == v.rdiff_signature, v.name
      end
    end

    test "rdiff signatures decode" do
      for v <- Vectors.signatures() do
        assert {:ok, sig} = Signature.decode(v.rdiff_signature), v.name

        assert sig ==
                 Rexd.signature(v.basis, block_len: v.block_len, strong_sum_len: v.strong_sum_len)
      end
    end
  end

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    property "our signature equals rdiff signature (3a) and rdiff's decodes (3d)", %{tmp_dir: dir} do
      check all basis <- binary(max_length: 5000),
                block_len <- member_of([1, 2, 3, 16, 64, 100, 128, 256, 1000, 2048]),
                strong_sum_len <- member_of([1, 8, 16, 31, 32]),
                max_runs: 60 do
        theirs = Oracle.rdiff_signature(basis, block_len, strong_sum_len, dir)
        ours = Rexd.signature(basis, block_len: block_len, strong_sum_len: strong_sum_len)
        assert IO.iodata_to_binary(Signature.encode(ours)) == theirs
        assert Signature.decode(theirs) == {:ok, ours}
      end
    end

    test "recommended_block_len/1 matches rdiff's default choice", %{tmp_dir: dir} do
      for size <- [0, 1, 65_536, 65_537, 70_000, 1_000_000, 3_000_000] do
        basis = :binary.copy(<<0>>, size)
        path = Path.join(dir, "rec")
        File.write!(path, basis)
        {_, 0} = System.cmd("rdiff", ["-f", "signature", path, path <> ".sig"])
        <<_magic::32, block_len::32, _::binary>> = File.read!(path <> ".sig")
        assert Rexd.recommended_block_len(size) == block_len, "size #{size}"
      end
    end
  end
end
