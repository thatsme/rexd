defmodule Rexd.Blake2bTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Rexd.Blake2b
  alias Rexd.Test.{Oracle, Vectors}

  doctest Blake2b

  test "matches committed b2sum -l 256 digests" do
    for {data, digest} <- Vectors.blake2b() do
      assert Blake2b.hash(data) == digest, "length #{byte_size(data)}"
    end
  end

  test "is not a prefix of BLAKE2b-512" do
    refute Blake2b.hash("abc") == binary_part(:crypto.hash(:blake2b, "abc"), 0, 32)
  end

  test "digest is always 32 bytes" do
    for len <- [0, 1, 127, 128, 129, 10_000] do
      assert byte_size(Blake2b.hash(:binary.copy(<<7>>, len))) == 32
    end
  end

  describe "oracle" do
    @describetag :b2sum
    @describetag :tmp_dir

    property "matches b2sum -l 256", %{tmp_dir: dir} do
      check all(data <- binary(max_length: 1024), max_runs: 50) do
        assert Blake2b.hash(data) == Oracle.b2sum256(data, dir)
      end
    end
  end
end
