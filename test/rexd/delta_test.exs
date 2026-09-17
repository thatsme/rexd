defmodule Rexd.DeltaTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.{Delta, Signature}
  alias Rexd.Test.{Oracle, Vectors}

  # -- generators ---------------------------------------------------------------

  defp basis_gen do
    one_of([
      binary(max_length: 3000),
      map(integer(0..3000), &:binary.copy(<<0>>, &1)),
      map(binary(min_length: 1, max_length: 40), &:binary.copy(&1, 30))
    ])
  end

  defp edit_gen do
    one_of([
      tuple({constant(:insert), integer(0..100_000), binary(min_length: 1, max_length: 200)}),
      tuple({constant(:delete), integer(0..100_000), integer(1..500)}),
      tuple({constant(:replace), integer(0..100_000), binary(min_length: 1, max_length: 200)}),
      tuple({constant(:move), integer(0..100_000), integer(1..500), integer(0..100_000)}),
      constant(:truncate),
      constant(:clear)
    ])
  end

  defp apply_edit(data, {:insert, at, bytes}) do
    at = rem(at, byte_size(data) + 1)
    <<a::binary-size(at), b::binary>> = data
    a <> bytes <> b
  end

  defp apply_edit(data, {:delete, at, len}) do
    at = rem(at, byte_size(data) + 1)
    len = min(len, byte_size(data) - at)
    <<a::binary-size(at), _::binary-size(len), b::binary>> = data
    a <> b
  end

  defp apply_edit(data, {:replace, at, bytes}) do
    at = rem(at, byte_size(data) + 1)
    len = min(byte_size(bytes), byte_size(data) - at)
    <<a::binary-size(at), _::binary-size(len), b::binary>> = data
    a <> binary_part(bytes, 0, len) <> b
  end

  defp apply_edit(data, {:move, from, len, to}) do
    from = rem(from, byte_size(data) + 1)
    len = min(len, byte_size(data) - from)
    <<a::binary-size(from), moved::binary-size(len), b::binary>> = data
    rest = a <> b
    to = rem(to, byte_size(rest) + 1)
    <<c::binary-size(to), d::binary>> = rest
    c <> moved <> d
  end

  defp apply_edit(data, :truncate), do: binary_part(data, 0, div(byte_size(data), 3))
  defp apply_edit(_data, :clear), do: <<>>

  defp case_gen do
    gen all basis <- basis_gen(),
            edits <- list_of(edit_gen(), max_length: 4),
            block_len <- member_of([1, 2, 3, 7, 16, 64, 128, 256, 1024, 2048]),
            strong_sum_len <- member_of([8, 16, 32]) do
      {basis, Enum.reduce(edits, basis, &apply_edit(&2, &1)), block_len, strong_sum_len}
    end
  end

  defp round_trip(basis, new, block_len, strong_sum_len \\ 32) do
    sig = Rexd.signature(basis, block_len: block_len, strong_sum_len: strong_sum_len)
    delta = Rexd.delta(sig, new)
    {delta, Rexd.patch(basis, delta)}
  end

  defp encode(delta), do: delta |> Delta.encode() |> IO.iodata_to_binary()

  defp assert_canonical(%Delta{commands: commands}) do
    commands
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.each(fn
      [{:literal, _}, {:literal, _}] -> flunk("adjacent literals in #{inspect(commands)}")
      [{:copy, o, l}, {:copy, o2, _}] when o + l == o2 -> flunk("uncoalesced copies")
      _ -> :ok
    end)

    for {:literal, <<>>} <- commands, do: flunk("empty literal")
    for {:copy, _, 0} <- commands, do: flunk("empty copy")
  end

  # -- round trip ---------------------------------------------------------------

  property "patch(basis, delta(signature(basis), new)) == {:ok, new}" do
    check all {basis, new, block_len, strong_sum_len} <- case_gen(), max_runs: 500 do
      {delta, patched} = round_trip(basis, new, block_len, strong_sum_len)
      assert patched == {:ok, new}
      assert_canonical(delta)
      assert Delta.decode(encode(delta)) == {:ok, delta}
    end
  end

  property "identical input is a single copy" do
    check all basis <- binary(min_length: 1, max_length: 5000), block_len <- integer(1..300) do
      {delta, {:ok, ^basis}} = round_trip(basis, basis, block_len)
      assert delta.commands == [{:copy, 0, byte_size(basis)}]
    end
  end

  property "deterministic encoding" do
    check all {basis, new, block_len, strong_sum_len} <- case_gen() do
      {a, _} = round_trip(basis, new, block_len, strong_sum_len)
      {b, _} = round_trip(basis, new, block_len, strong_sum_len)
      assert encode(a) == encode(b)
    end
  end

  describe "edge cases" do
    test "empty basis: one literal" do
      assert {%Delta{commands: [{:literal, "hello"}]}, {:ok, "hello"}} =
               round_trip("", "hello", 4)
    end

    test "empty new: no commands" do
      assert {%Delta{commands: []}, {:ok, ""}} = round_trip("hello", "", 4)
      assert encode(%Delta{commands: []}) == <<0x72730236::32, 0>>
    end

    test "block_len larger than both inputs" do
      assert {%Delta{commands: [{:copy, 0, 3}]}, {:ok, "abc"}} = round_trip("abc", "abc", 2048)

      assert {%Delta{commands: [{:literal, "abd"}]}, {:ok, "abd"}} =
               round_trip("abc", "abd", 2048)
    end

    test "input exactly k * block_len" do
      basis = for i <- 0..63, into: <<>>, do: <<i>>
      <<b0::binary-16, b1::binary-16, b2::binary-16, b3::binary-16>> = basis
      new = b2 <> b3 <> b0 <> b1

      assert {%Delta{commands: [{:copy, 32, 32}, {:copy, 0, 32}]}, {:ok, ^new}} =
               round_trip(basis, new, 16)
    end

    test "short last block matched at the end of new" do
      basis = "0123456789abcdefXYZ"
      new = "prefix-" <> "0123456789abcdef" <> "XYZ"
      assert {%Delta{commands: commands}, {:ok, ^new}} = round_trip(basis, new, 16)
      assert commands == [{:literal, "prefix-"}, {:copy, 0, 19}]
    end

    test "short last block is not matched away from the end of new" do
      basis = "0123456789abcdefXYZ"
      new = "XYZ" <> "0123456789abcdef"

      assert {%Delta{commands: [{:literal, "XYZ"}, {:copy, 0, 16}]}, {:ok, ^new}} =
               round_trip(basis, new, 16)
    end

    test "all-zero weak-hash collision storm coalesces" do
      zeros = :binary.copy(<<0>>, 64 * 1000)
      sig = Rexd.signature(zeros, block_len: 64)
      assert map_size(Signature.build_index(sig).index) == 1

      assert Rexd.delta(sig, zeros).commands == [{:copy, 0, 64_000}]

      new = :binary.copy(<<0>>, 64 * 500) <> "x" <> :binary.copy(<<0>>, 64 * 400 + 10)
      delta = Rexd.delta(sig, new)
      assert Rexd.patch(zeros, delta) == {:ok, new}
      assert length(delta.commands) <= 4
    end

    test "reuses a prebuilt index" do
      sig = "abcdefgh" |> Rexd.signature(block_len: 4) |> Signature.build_index()
      assert Rexd.delta(sig, "efghabcd").commands == [{:copy, 4, 4}, {:copy, 0, 4}]
    end
  end

  describe "weak hash false hits" do
    test "rate on unrelated random data is negligible" do
      basis = :crypto.strong_rand_bytes(1_000_000)
      new = :crypto.strong_rand_bytes(1_000_000)
      sig = Rexd.signature(basis, block_len: 128)
      {delta, stats} = Delta.compute_with_stats(sig, new)
      assert Rexd.patch(basis, delta) == {:ok, new}
      windows = byte_size(new)
      # ~7800 blocks against ~1M windows: expected false hits ~ 1M * 7800 / 2^32 ~ 2.
      assert stats.false_weak_hits == stats.weak_hits
      assert stats.false_weak_hits / windows < 1.0e-4
    end

    test "rate on low-entropy text" do
      words = ~w(the quick brown fox jumps over lazy dog and cat sat on mat a an)

      text = fn seed, n ->
        :rand.seed(:exsss, {seed, seed, seed})
        Enum.map_join(1..n, " ", fn _ -> Enum.random(words) end)
      end

      basis = text.(1, 100_000)
      new = text.(2, 100_000)
      sig = Rexd.signature(basis, block_len: 64)
      {delta, stats} = Delta.compute_with_stats(sig, new)
      assert Rexd.patch(basis, delta) == {:ok, new}
      assert stats.false_weak_hits / byte_size(new) < 1.0e-3
    end
  end

  # -- wire format --------------------------------------------------------------

  describe "encode/1 opcode selection (emit.c)" do
    test "literals" do
      assert encode(%Delta{commands: [{:literal, "a"}]}) == <<0x72730236::32, 0x01, "a", 0>>

      l64 = :binary.copy("x", 64)

      assert encode(%Delta{commands: [{:literal, l64}]}) ==
               <<0x72730236::32, 0x40, l64::binary, 0>>

      l65 = :binary.copy("x", 65)

      assert encode(%Delta{commands: [{:literal, l65}]}) ==
               <<0x72730236::32, 0x41, 65, l65::binary, 0>>

      l256 = :binary.copy("x", 256)

      assert encode(%Delta{commands: [{:literal, l256}]}) ==
               <<0x72730236::32, 0x42, 256::16, l256::binary, 0>>
    end

    test "copies pick offset and length widths independently" do
      cases = [
        {{0, 1}, <<0x45, 0, 1>>},
        {{255, 256}, <<0x46, 255, 256::16>>},
        {{256, 70_000}, <<0x4B, 256::16, 70_000::32>>},
        {{70_000, 1}, <<0x4D, 70_000::32, 1>>},
        {{1 <<< 32, 1 <<< 32}, <<0x54, 1 <<< 32::64, 1 <<< 32::64>>}
      ]

      for {{off, len}, bytes} <- cases do
        assert encode(%Delta{commands: [{:copy, off, len}]}) ==
                 <<0x72730236::32, bytes::binary, 0>>
      end
    end

    test "zero-length commands are omitted" do
      assert encode(%Delta{commands: [{:literal, ""}, {:copy, 5, 0}]}) == <<0x72730236::32, 0>>
    end
  end

  describe "decode/1" do
    property "round-trips arbitrary non-empty commands" do
      command =
        one_of([
          map(binary(min_length: 1, max_length: 300), &{:literal, &1}),
          map(tuple({integer(0..0xFFFFFFFFFF), integer(1..0xFFFFFFFFFF)}), fn {o, l} ->
            {:copy, o, l}
          end)
        ])

      check all commands <- list_of(command, max_length: 20) do
        delta = %Delta{commands: commands}
        assert Delta.decode(encode(delta)) == {:ok, delta}
      end
    end

    test "accepts LITERAL_N8, which librsync does not emit" do
      assert Delta.decode(<<0x72730236::32, 0x44, 3::64, "abc", 0>>) ==
               {:ok, %Delta{commands: [{:literal, "abc"}]}}
    end

    test "errors" do
      m = <<0x72730236::32>>
      assert Delta.decode(<<>>) == {:error, :truncated_header}
      assert Delta.decode(<<0x72730147::32, 0>>) == {:error, {:bad_magic, 0x72730147}}
      assert Delta.decode(m) == {:error, :missing_end}
      assert Delta.decode(m <> <<0x01, "a">>) == {:error, :missing_end}
      assert Delta.decode(m <> <<0, 0>>) == {:error, :trailing_data}
      assert Delta.decode(m <> <<0x55>>) == {:error, {:reserved_opcode, 0x55}}
      assert Delta.decode(m <> <<0x03, "ab">>) == {:error, :truncated}
      assert Delta.decode(m <> <<0x41, 10, "abc">>) == {:error, :truncated}
      assert Delta.decode(m <> <<0x4F, 0, 0>>) == {:error, :truncated}
    end
  end

  describe "patch/2" do
    test "rejects copies past the end of the basis" do
      assert Rexd.patch("abc", %Delta{commands: [{:copy, 1, 3}]}) ==
               {:error, {:copy_out_of_range, 1, 3}}

      assert Rexd.patch("abc", %Delta{commands: [{:copy, 3, 0}]}) == {:ok, ""}
    end
  end

  # -- librsync compatibility ---------------------------------------------------

  describe "committed rdiff vectors" do
    test "rdiff deltas decode and patch with patch/2" do
      for v <- Vectors.signatures() do
        assert {:ok, delta} = Delta.decode(v.rdiff_delta), v.name
        assert Rexd.patch(v.basis, delta) == {:ok, v.new}, v.name
      end
    end

    test "our deltas re-encode losslessly and patch" do
      for v <- Vectors.signatures() do
        {delta, patched} = round_trip(v.basis, v.new, v.block_len, v.strong_sum_len)
        assert patched == {:ok, v.new}, v.name
        assert Delta.decode(encode(delta)) == {:ok, delta}, v.name
      end
    end
  end

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    property "rdiff delta against our signature patches with patch/2 (3b)", %{tmp_dir: dir} do
      check all {basis, new, block_len, strong_sum_len} <- case_gen(), max_runs: 60 do
        sig = Rexd.signature(basis, block_len: block_len, strong_sum_len: strong_sum_len)
        rdiff_delta = Oracle.rdiff_delta(IO.iodata_to_binary(Signature.encode(sig)), new, dir)
        assert {:ok, delta} = Delta.decode(rdiff_delta)
        assert Rexd.patch(basis, delta) == {:ok, new}
      end
    end

    property "our delta patches with rdiff patch (3c)", %{tmp_dir: dir} do
      check all {basis, new, block_len, strong_sum_len} <- case_gen(), max_runs: 60 do
        {delta, _} = round_trip(basis, new, block_len, strong_sum_len)
        assert Oracle.rdiff_patch(basis, encode(delta), dir) == new
      end
    end

    test "large literal and copy arguments", %{tmp_dir: dir} do
      basis = :crypto.strong_rand_bytes(300_000)
      new = :crypto.strong_rand_bytes(70_000) <> basis <> :crypto.strong_rand_bytes(100)
      {delta, {:ok, ^new}} = round_trip(basis, new, 2048)
      assert Oracle.rdiff_patch(basis, encode(delta), dir) == new
    end
  end
end
