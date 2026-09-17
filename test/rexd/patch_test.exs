defmodule Rexd.PatchTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.Delta
  alias Rexd.Test.Oracle

  defp delta(commands), do: %Delta{commands: commands}

  describe "copy bounds" do
    test "copies inside the basis, including zero-length at the end" do
      assert Rexd.patch("abcdef", delta([{:copy, 4, 2}, {:copy, 0, 2}])) == {:ok, "efab"}
      assert Rexd.patch("abc", delta([{:copy, 0, 3}])) == {:ok, "abc"}
      assert Rexd.patch("abc", delta([{:copy, 3, 0}])) == {:ok, ""}
    end

    test "copies past the end of the basis are rejected" do
      assert Rexd.patch("abc", delta([{:copy, 1, 3}])) == {:error, {:copy_out_of_range, 1, 3}}
      assert Rexd.patch("abc", delta([{:copy, 4, 0}])) == {:error, {:copy_out_of_range, 4, 0}}
      assert Rexd.patch("", delta([{:copy, 0, 1}])) == {:error, {:copy_out_of_range, 0, 1}}
    end

    test "an out-of-range copy after valid commands still fails without output" do
      commands = [{:literal, "xyz"}, {:copy, 0, 3}, {:copy, 2, 5}]
      assert Rexd.patch("abcd", delta(commands)) == {:error, {:copy_out_of_range, 2, 5}}
    end

    test "empty delta patches to empty output" do
      assert Rexd.patch("anything", delta([])) == {:ok, ""}
    end
  end

  describe ":max_size" do
    test "limits the output size before building it" do
      d = delta([{:copy, 0, 4}, {:copy, 0, 4}, {:literal, "!"}])
      assert Rexd.patch("abcd", d, max_size: 9) == {:ok, "abcdabcd!"}
      assert Rexd.patch("abcd", d, max_size: 8) == {:error, {:output_too_large, 9, 8}}
      assert Rexd.patch("abcd", d, max_size: :infinity) == {:ok, "abcdabcd!"}
    end

    test "a small delta describing a large output is caught" do
      basis = :binary.copy(<<0>>, 1_000_000)
      bomb = delta(List.duplicate({:copy, 0, 1_000_000}, 10_000))
      assert bomb |> Delta.encode() |> IO.iodata_to_binary() |> byte_size() < 100_000

      assert Rexd.patch(basis, bomb, max_size: 100_000_000) ==
               {:error, {:output_too_large, 10_000_000_000, 100_000_000}}
    end

    test "range errors take precedence over size errors" do
      assert Rexd.patch("ab", delta([{:copy, 0, 5}]), max_size: 1) ==
               {:error, {:copy_out_of_range, 0, 5}}
    end

    test "invalid options raise" do
      assert_raise ArgumentError, fn -> Rexd.patch("a", delta([]), max_size: -1) end
      assert_raise ArgumentError, fn -> Rexd.patch("a", delta([]), max_size: "10") end
      assert_raise ArgumentError, fn -> Rexd.patch("a", delta([]), bogus: true) end
    end
  end

  describe "untrusted input" do
    property "decoding and patching arbitrary bytes returns a result, never raises" do
      check all basis <- binary(max_length: 200),
                body <- binary(max_length: 64),
                max_runs: 2_000 do
        case Delta.decode(<<0x72730236::32, body::binary>>) do
          {:ok, d} ->
            assert match?(
                     {tag, _} when tag in [:ok, :error],
                     Rexd.patch(basis, d, max_size: 10_000)
                   )

          {:error, _reason} ->
            :ok
        end
      end
    end

    property "a delta applied to the wrong basis returns a result, never raises" do
      check all basis <- binary(max_length: 2000),
                other <- binary(max_length: 2000),
                new <- binary(max_length: 2000),
                block_len <- member_of([4, 16, 64]) do
        d = Rexd.delta(Rexd.signature(basis, block_len: block_len), new)
        assert match?({tag, _} when tag in [:ok, :error], Rexd.patch(other, d))
      end
    end
  end

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    test "rdiff patch rejects the corrupt deltas decode/1 rejects", %{tmp_dir: dir} do
      m = <<0x72730236::32>>

      for bytes <- [<<0x41, 0, 0>>, <<0x45, 0, 0, 0>>, <<0x51, 1 <<< 63::64, 1, 0>>] do
        wire = m <> bytes
        assert {:error, _} = Delta.decode(wire)
        assert {:error, _} = Oracle.rdiff_patch_result("abc", wire, dir)
      end
    end

    test "rdiff patch rejects an out-of-range copy, as patch/3 does", %{tmp_dir: dir} do
      wire = <<0x72730236::32, 0x45, 1, 3, 0>>
      assert {:ok, d} = Delta.decode(wire)
      assert {:error, {:copy_out_of_range, 1, 3}} = Rexd.patch("abc", d)
      assert {:error, _} = Oracle.rdiff_patch_result("abc", wire, dir)
    end
  end
end
