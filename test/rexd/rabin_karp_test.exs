defmodule Rexd.RabinKarpTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.RabinKarp

  describe "hash/1" do
    test "matches the librsync weak sum for a known block" do
      # rdiff signature -b 2048 -S 32 over this 25-byte input yields weak 0xa18f3b3c
      assert RabinKarp.hash("hello world, this is rexd") == 0xA18F3B3C
    end

    test "update/2 is incremental" do
      check all a <- binary(), b <- binary() do
        assert RabinKarp.update(RabinKarp.hash(a), b) == RabinKarp.hash(a <> b)
      end
    end

    test "rollin/2 matches update/2 byte by byte" do
      check all data <- binary() do
        rolled = for <<b <- data>>, reduce: RabinKarp.seed(), do: (h -> RabinKarp.rollin(h, b))
        assert rolled == RabinKarp.hash(data)
      end
    end
  end

  describe "pow/1" do
    test "agrees with repeated multiplication" do
      Enum.reduce(0..300, 1, fn n, acc ->
        assert RabinKarp.pow(n) == acc
        rem(acc * 0x08104225, 0x100000000)
      end)
    end

    test "handles large exponents" do
      assert RabinKarp.pow(1 <<< 32) == 1
      assert RabinKarp.pow(1 <<< 40) == 1
    end
  end

  describe "rotate/5" do
    property "rolling equals from-scratch at every offset" do
      check all n <- integer(1..64),
                data <- binary(min_length: n, max_length: n + 200) do
        {mult_n, adj_n} = RabinKarp.window(n)
        last = byte_size(data) - n
        h0 = RabinKarp.hash(binary_part(data, 0, n))

        Enum.reduce(0..last, h0, fn pos, h ->
          assert h == RabinKarp.hash(binary_part(data, pos, n))

          if pos < last do
            RabinKarp.rotate(h, :binary.at(data, pos), :binary.at(data, pos + n), mult_n, adj_n)
          else
            h
          end
        end)
      end
    end

    test "all-zero and all-0xFF windows" do
      for byte <- [0, 255], n <- [1, 2, 128, 2048] do
        data = :binary.copy(<<byte>>, n + 50)
        {mult_n, adj_n} = RabinKarp.window(n)
        h = RabinKarp.hash(binary_part(data, 0, n))
        h = RabinKarp.rotate(h, byte, byte, mult_n, adj_n)
        assert h == RabinKarp.hash(binary_part(data, 1, n))
      end
    end
  end

  describe "rollout/4" do
    property "shrinking the window equals hashing the suffix" do
      check all data <- binary(min_length: 1, max_length: 300) do
        n = byte_size(data)

        Enum.reduce(0..(n - 1), RabinKarp.hash(data), fn pos, h ->
          {mult, adj} = RabinKarp.window(n - pos - 1)
          h = RabinKarp.rollout(h, :binary.at(data, pos), mult, adj)
          assert h == RabinKarp.hash(binary_part(data, pos + 1, n - pos - 1))
          h
        end)
      end
    end
  end
end
