defmodule Rexd.StreamTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.{Delta, Signature, StreamError}
  alias Rexd.Delta.Search
  alias Rexd.Test.Oracle

  doctest Rexd.Stream

  # -- helpers ------------------------------------------------------------------

  # Splits `data` into consecutive pieces whose sizes cycle through `sizes`.
  defp split(data, sizes),
    do: split(data, Stream.cycle(sizes) |> Enum.take(byte_size(data) + 1), [])

  defp split(<<>>, _sizes, acc), do: Enum.reverse(acc)

  defp split(data, [size | sizes], acc) do
    take = min(size, byte_size(data))
    <<piece::binary-size(take), rest::binary>> = data
    split(rest, sizes, [piece | acc])
  end

  defp chunk_sizes, do: list_of(integer(1..5000), min_length: 1, max_length: 8)

  defp encode_sig(sig), do: sig |> Signature.encode() |> IO.iodata_to_binary()
  defp encode_delta(delta), do: delta |> Delta.encode() |> IO.iodata_to_binary()

  defp reader(basis) do
    fn offset, len ->
      binary_part(
        basis,
        min(offset, byte_size(basis)),
        min(len, max(byte_size(basis) - offset, 0))
      )
    end
  end

  defp merge_literals(commands) do
    commands
    |> Enum.chunk_while(
      nil,
      fn
        {:literal, data}, {:literal, acc} -> {:cont, {:literal, acc <> data}}
        command, nil -> {:cont, command}
        command, previous -> {:cont, previous, command}
      end,
      fn
        nil -> {:cont, nil}
        previous -> {:cont, previous, nil}
      end
    )
  end

  defp edited(basis, cut, insert) do
    cut = rem(cut, byte_size(basis) + 1)
    <<a::binary-size(cut), b::binary>> = basis
    b <> insert <> a
  end

  # -- signature ----------------------------------------------------------------

  property "signature/2 output equals Signature.encode/1 for any chunking" do
    check all basis <- binary(max_length: 20_000),
              sizes <- chunk_sizes(),
              block_len <- member_of([1, 7, 64, 1000, 2048]),
              strong_sum_len <- member_of([4, 32]) do
      opts = [block_len: block_len, strong_sum_len: strong_sum_len]
      streamed = basis |> split(sizes) |> Rexd.Stream.signature(opts) |> Enum.join()
      assert streamed == encode_sig(Rexd.signature(basis, opts))
    end
  end

  test "signature/2 of an empty stream is the header alone" do
    assert [] |> Rexd.Stream.signature(block_len: 16) |> Enum.join() ==
             encode_sig(Rexd.signature("", block_len: 16))
  end

  # -- delta: resumable search ---------------------------------------------------

  property "feeding in pieces finds the same matches as the whole-binary search" do
    check all basis <- binary(max_length: 3000),
              insert <- binary(max_length: 300),
              cut <- integer(0..3000),
              sizes <- list_of(integer(1..200), min_length: 1, max_length: 8),
              block_len <- member_of([1, 3, 16, 64, 256]),
              max_literal <- one_of([constant(:infinity), integer(1..100)]) do
      new = edited(basis, cut, insert)
      sig = Rexd.signature(basis, block_len: block_len)

      {fed, search} =
        new
        |> split(sizes)
        |> Enum.reduce({[], Search.new(sig, max_literal)}, fn chunk, {acc, search} ->
          {ready, search} = Search.feed(search, chunk)
          {acc ++ ready, search}
        end)

      {rest, _stats} = Search.finish(search)
      streamed = fed ++ rest
      whole = Rexd.delta(sig, new).commands

      assert merge_literals(streamed) == whole
      assert Rexd.patch(basis, %Delta{commands: streamed}) == {:ok, new}
    end
  end

  test "the search buffer stays bounded" do
    basis = :crypto.strong_rand_bytes(200_000)
    new = :crypto.strong_rand_bytes(500_000) <> basis <> :crypto.strong_rand_bytes(300_000)
    block_len = 1024
    max_literal = 8192
    chunk = 4096

    search = Search.new(Rexd.signature(basis, block_len: block_len), max_literal)

    {commands, search} =
      new
      |> split([chunk])
      |> Enum.reduce({[], search}, fn piece, {commands, search} ->
        {ready, search} = Search.feed(search, piece)
        assert search.ctx.size <= 2 * (max_literal + block_len + chunk)
        {[ready | commands], search}
      end)

    {rest, _stats} = Search.finish(search)
    commands = commands |> Enum.reverse() |> Enum.concat() |> Enum.concat(rest)
    assert Rexd.patch(basis, %Delta{commands: commands}) == {:ok, new}
  end

  # -- delta: stream ---------------------------------------------------------------

  property "delta/2 output patches to the new data for any chunking" do
    check all basis <- binary(max_length: 5000),
              insert <- binary(max_length: 500),
              cut <- integer(0..5000),
              sizes <- chunk_sizes(),
              block_len <- member_of([4, 64, 512]) do
      new = edited(basis, cut, insert)
      sig = Rexd.signature(basis, block_len: block_len)
      encoded = sig |> Rexd.Stream.delta(split(new, sizes)) |> Enum.join()

      assert {:ok, delta} = Delta.decode(encoded)
      assert Rexd.patch(basis, delta) == {:ok, new}
      assert encoded == encode_delta(Rexd.delta(sig, new))
    end
  end

  test "delta/2 over inputs larger than the literal cap" do
    basis = :crypto.strong_rand_bytes(300_000)

    new =
      :crypto.strong_rand_bytes(200_000) <>
        binary_part(basis, 5000, 150_000) <> :crypto.strong_rand_bytes(70_000)

    sig = Rexd.signature(basis, block_len: 2048)

    for sizes <- [[1_000_000], [65_536], [4096, 7], [100_000, 1]] do
      encoded = sig |> Rexd.Stream.delta(split(new, sizes)) |> Enum.join()
      assert {:ok, delta} = Delta.decode(encoded)
      assert Rexd.patch(basis, delta) == {:ok, new}
      assert merge_literals(delta.commands) == Rexd.delta(sig, new).commands
    end
  end

  test "delta/2 with an empty stream or an empty signature" do
    sig = Rexd.signature("abc", block_len: 2)
    assert sig |> Rexd.Stream.delta([]) |> Enum.join() == encode_delta(%Delta{commands: []})

    empty = Rexd.signature("", block_len: 2)
    encoded = empty |> Rexd.Stream.delta(["he", "llo"]) |> Enum.join()
    assert encoded == encode_delta(%Delta{commands: [{:literal, "hello"}]})
  end

  # -- patch --------------------------------------------------------------------

  property "patch/3 rebuilds the data for any chunking of the delta" do
    check all basis <- binary(max_length: 5000),
              insert <- binary(max_length: 500),
              cut <- integer(0..5000),
              sizes <- list_of(integer(1..50), min_length: 1, max_length: 8),
              block_len <- member_of([4, 64]) do
      new = edited(basis, cut, insert)
      encoded = encode_delta(Rexd.delta(Rexd.signature(basis, block_len: block_len), new))
      assert reader(basis) |> Rexd.Stream.patch(split(encoded, sizes)) |> Enum.join() == new
    end
  end

  test "patch/3 reads large copies in bounded pieces, lazily" do
    test_pid = self()
    basis = :binary.copy(<<7>>, 1_000_000)

    read = fn offset, len ->
      send(test_pid, {:read, offset, len})
      binary_part(basis, offset, len)
    end

    encoded = encode_delta(%Delta{commands: [{:copy, 0, 1_000_000}]})
    assert [first] = read |> Rexd.Stream.patch([encoded]) |> Enum.take(1)
    assert byte_size(first) == 65_536
    assert_received {:read, 0, 65_536}
    refute_received {:read, _, _}

    assert read |> Rexd.Stream.patch([encoded]) |> Enum.join() == basis
  end

  test "patch/3 passes literal data through before the literal is complete" do
    data = :crypto.strong_rand_bytes(100_000)
    <<wire::binary-size(50_000), _::binary>> = encode_delta(%Delta{commands: [{:literal, data}]})
    input = Stream.concat([wire], Stream.map([:never], fn _ -> raise "input read too far" end))

    assert [first] = reader("") |> Rexd.Stream.patch(input) |> Enum.take(1)
    assert data |> binary_part(0, byte_size(first)) == first
  end

  describe "patch/3 errors" do
    defp patch_reason(basis, chunks, opts \\ []) do
      error =
        assert_raise(StreamError, fn ->
          reader(basis) |> Rexd.Stream.patch(chunks, opts) |> Enum.join()
        end)

      error.reason
    end

    test "every proper prefix of a valid delta is rejected" do
      basis = :crypto.strong_rand_bytes(2000)
      new = "x" <> binary_part(basis, 100, 1500) <> :crypto.strong_rand_bytes(100)
      encoded = encode_delta(Rexd.delta(Rexd.signature(basis, block_len: 64), new))

      for cut <- 0..(byte_size(encoded) - 1) do
        prefix = binary_part(encoded, 0, cut)
        assert patch_reason(basis, [prefix]) in [:truncated_header, :missing_end, :truncated]
      end
    end

    test "corrupt input" do
      m = <<0x72730236::32>>
      assert patch_reason("abc", [<<0x72730147::32, 0>>]) == {:bad_magic, 0x72730147}
      assert patch_reason("abc", [m, <<0, 1>>]) == :trailing_data
      assert patch_reason("abc", [m, <<0x55>>]) == {:reserved_opcode, 0x55}
      assert patch_reason("abc", [m, <<0x41, 0>>]) == {:zero_length, :literal}

      assert patch_reason("abc", [m, <<0x54, 1 <<< 63::64, 1::64>>]) ==
               {:argument_too_large, 1 <<< 63}
    end

    test "copies past the end of the basis" do
      m = <<0x72730236::32>>
      assert patch_reason("abc", [m <> <<0x45, 1, 3, 0>>]) == {:copy_out_of_range, 1, 3}
    end

    test "max_size" do
      encoded = encode_delta(%Delta{commands: [{:copy, 0, 3}, {:literal, "xy"}]})
      assert reader("abc") |> Rexd.Stream.patch([encoded], max_size: 5) |> Enum.join() == "abcxy"
      assert patch_reason("abc", [encoded], max_size: 4) == {:output_too_large, 5, 4}
    end

    test "invalid options raise when called" do
      assert_raise ArgumentError, fn -> Rexd.Stream.patch(reader(""), [], max_size: -1) end
      assert_raise ArgumentError, fn -> Rexd.Stream.signature([], block_len: 0) end
    end
  end

  # -- librsync -----------------------------------------------------------------

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    property "streamed signature equals rdiff signature", %{tmp_dir: dir} do
      check all basis <- binary(max_length: 10_000), sizes <- chunk_sizes(), max_runs: 25 do
        streamed =
          basis
          |> split(sizes)
          |> Rexd.Stream.signature(block_len: 128, strong_sum_len: 16)
          |> Enum.join()

        assert streamed == Oracle.rdiff_signature(basis, 128, 16, dir)
      end
    end

    test "rdiff patch applies a streamed delta; streamed patch applies an rdiff delta", %{
      tmp_dir: dir
    } do
      basis = :crypto.strong_rand_bytes(400_000)

      new =
        :crypto.strong_rand_bytes(100_000) <>
          binary_part(basis, 1000, 250_000) <> :crypto.strong_rand_bytes(90_000)

      sig = Rexd.signature(basis, block_len: 2048)

      ours = sig |> Rexd.Stream.delta(split(new, [30_000, 1])) |> Enum.join()
      assert Oracle.rdiff_patch(basis, ours, dir) == new

      theirs = Oracle.rdiff_delta(encode_sig(sig), new, dir)
      assert reader(basis) |> Rexd.Stream.patch(split(theirs, [777])) |> Enum.join() == new
    end
  end
end
