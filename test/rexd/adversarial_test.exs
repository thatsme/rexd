defmodule Rexd.AdversarialTest do
  # Hostile or corrupted input: every public entry point must answer with an
  # error tuple (or Rexd.StreamError for streams) in bounded time and memory,
  # never with another exception.
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Rexd.{Delta, RabinKarp, Signature, StreamError}

  @max_size 1_000_000

  # -- generators ---------------------------------------------------------------

  defp mutation do
    one_of([
      tuple({constant(:flip), integer(0..100_000), integer(0..7)}),
      tuple({constant(:set), integer(0..100_000), integer(0..255)}),
      tuple({constant(:insert), integer(0..100_000), binary(min_length: 1, max_length: 16)}),
      tuple({constant(:delete), integer(0..100_000), integer(1..16)}),
      tuple({constant(:truncate), integer(0..100_000)})
    ])
  end

  defp mutate(<<>>, _mutation), do: <<>>

  defp mutate(bytes, {:flip, at, bit}) do
    at = rem(at, byte_size(bytes))
    <<a::binary-size(at), byte, b::binary>> = bytes
    <<a::binary, bxor(byte, 1 <<< bit), b::binary>>
  end

  defp mutate(bytes, {:set, at, value}) do
    at = rem(at, byte_size(bytes))
    <<a::binary-size(at), _byte, b::binary>> = bytes
    <<a::binary, value, b::binary>>
  end

  defp mutate(bytes, {:insert, at, inserted}) do
    at = rem(at, byte_size(bytes) + 1)
    <<a::binary-size(at), b::binary>> = bytes
    a <> inserted <> b
  end

  defp mutate(bytes, {:delete, at, len}) do
    at = rem(at, byte_size(bytes))
    len = min(len, byte_size(bytes) - at)
    <<a::binary-size(at), _::binary-size(len), b::binary>> = bytes
    a <> b
  end

  defp mutate(bytes, {:truncate, at}), do: binary_part(bytes, 0, rem(at, byte_size(bytes)))

  defp mutated(bytes, mutations), do: Enum.reduce(mutations, bytes, &mutate(&2, &1))

  # A valid basis, new data, and their encoded signature and delta.
  defp valid_case do
    gen all basis <- binary(max_length: 2000),
            insert <- binary(max_length: 200),
            cut <- integer(0..2000),
            block_len <- member_of([1, 8, 64, 256]),
            strong_sum_len <- member_of([1, 8, 32]) do
      cut = rem(cut, byte_size(basis) + 1)
      <<a::binary-size(cut), b::binary>> = basis
      new = b <> insert <> a
      sig = Rexd.signature(basis, block_len: block_len, strong_sum_len: strong_sum_len)

      %{
        basis: basis,
        new: new,
        signature: sig |> Signature.encode() |> IO.iodata_to_binary(),
        delta: sig |> Rexd.delta(new) |> Delta.encode() |> IO.iodata_to_binary()
      }
    end
  end

  defp reader(basis) do
    fn offset, len ->
      from = min(offset, byte_size(basis))
      binary_part(basis, from, min(len, byte_size(basis) - from))
    end
  end

  defp split(bytes, size) when byte_size(bytes) <= size, do: [bytes]

  defp split(bytes, size) do
    <<piece::binary-size(size), rest::binary>> = bytes
    [piece | split(rest, size)]
  end

  defp stream_patch_outcome(basis, bytes, chunk_size) do
    reader(basis)
    |> Rexd.Stream.patch(split(bytes, chunk_size), max_size: @max_size)
    |> Enum.join()
    |> then(&{:ok, &1})
  rescue
    error in StreamError -> {:error, error.reason}
  end

  defp tuple_result?({:ok, _}), do: true
  defp tuple_result?({:error, _}), do: true
  defp tuple_result?(_), do: false

  # -- corrupted deltas ---------------------------------------------------------

  property "mutated deltas: decode and patch return tuples, never raise" do
    check all c <- valid_case(),
              mutations <- list_of(mutation(), min_length: 1, max_length: 4),
              max_runs: 1_000 do
      bytes = mutated(c.delta, mutations)

      case Delta.decode(bytes) do
        {:ok, delta} -> assert tuple_result?(Rexd.patch(c.basis, delta, max_size: @max_size))
        {:error, _reason} -> :ok
      end
    end
  end

  property "mutated deltas: the streaming patch raises only Rexd.StreamError" do
    check all c <- valid_case(),
              mutations <- list_of(mutation(), min_length: 1, max_length: 4),
              chunk_size <- integer(1..64),
              max_runs: 1_000 do
      bytes = mutated(c.delta, mutations)
      assert tuple_result?(stream_patch_outcome(c.basis, bytes, chunk_size))
    end
  end

  property "streaming and whole-binary patch agree on every corrupted delta" do
    check all c <- valid_case(),
              mutations <- list_of(mutation(), min_length: 1, max_length: 4),
              chunk_size <- integer(1..64),
              max_runs: 1_000 do
      bytes = mutated(c.delta, mutations)

      whole =
        with {:ok, delta} <- Delta.decode(bytes),
             do: Rexd.patch(c.basis, delta, max_size: @max_size)

      assert stream_patch_outcome(c.basis, bytes, chunk_size) |> elem(0) == elem(whole, 0)
    end
  end

  property "random bytes after the delta magic" do
    check all body <- binary(max_length: 512), chunk_size <- integer(1..64), max_runs: 1_000 do
      bytes = <<Delta.magic()::32, body::binary>>
      assert tuple_result?(Delta.decode(bytes))
      assert tuple_result?(stream_patch_outcome("some basis", bytes, chunk_size))
    end
  end

  # -- corrupted signatures -----------------------------------------------------

  property "mutated signatures: decode returns a tuple; decoded ones drive delta safely" do
    check all c <- valid_case(),
              mutations <- list_of(mutation(), min_length: 1, max_length: 4),
              max_runs: 1_000 do
      case Signature.decode(mutated(c.signature, mutations)) do
        {:ok, sig} ->
          delta = Rexd.delta(sig, c.new)
          assert tuple_result?(Rexd.patch(c.basis, delta, max_size: @max_size))
          assert {:ok, _} = delta |> Delta.encode() |> IO.iodata_to_binary() |> Delta.decode()

        {:error, _reason} ->
          :ok
      end
    end
  end

  property "random bytes as a signature" do
    check all bytes <- binary(max_length: 512),
              max_runs: 1_000 do
      assert tuple_result?(Signature.decode(bytes))
      assert tuple_result?(Signature.decode(<<Signature.magic()::32, bytes::binary>>))
    end
  end

  test "a decoded signature with an extreme block length" do
    bytes = <<Signature.magic()::32, 0xFFFFFFFF::32, 32::32, 1::32, 0::256>>
    assert {:ok, sig} = Signature.decode(bytes)
    delta = Rexd.delta(sig, :crypto.strong_rand_bytes(10_000))
    assert [{:literal, _}] = delta.commands
  end

  # -- crafted checksum collisions ----------------------------------------------

  describe "a signature whose blocks all share one weak checksum" do
    defp colliding_signature(block_len, count, weak) do
      blocks = for i <- 1..count, do: {weak, <<i::256>>}
      %Signature{block_len: block_len, strong_sum_len: 32, blocks: blocks}
    end

    test "builds its index in linear time" do
      sig = colliding_signature(2048, 200_000, 12_345)
      {micros, indexed} = :timer.tc(fn -> Signature.build_index(sig) end)
      assert map_size(indexed.index[12_345]) == 200_000
      # Quadratic construction takes minutes here; linear takes well under a second.
      assert micros < 5_000_000
    end

    test "costs a constant-time lookup per matching window" do
      block_len = 64
      zeros = :binary.copy(<<0>>, 64_000)

      sig =
        colliding_signature(block_len, 50_000, RabinKarp.hash(binary_part(zeros, 0, block_len)))

      {micros, {delta, stats}} = :timer.tc(fn -> Delta.compute_with_stats(sig, zeros) end)
      assert delta.commands == [{:literal, zeros}]
      assert stats.false_weak_hits == byte_size(zeros) - block_len + 1
      # A linear scan of 50 000 candidates per window takes minutes here.
      assert micros < 5_000_000
    end
  end

  # -- implausible lengths --------------------------------------------------------

  describe "lengths far beyond the data" do
    test "a literal claiming 2^62 bytes" do
      bytes = <<Delta.magic()::32, 0x44, 1 <<< 62::64, "abc">>
      assert Delta.decode(bytes) == {:error, :truncated}

      assert stream_patch_outcome("", bytes, 7) ==
               {:error, {:output_too_large, 1 <<< 62, @max_size}}
    end

    test "a literal claiming 2^62 bytes, without a size limit, passes data through then fails" do
      bytes = <<Delta.magic()::32, 0x44, 1 <<< 62::64, "abc">>
      stream = Rexd.Stream.patch(reader(""), [bytes])
      error = assert_raise StreamError, fn -> Enum.to_list(stream) end
      assert error.reason == :truncated
    end

    test "a copy of 2^62 bytes" do
      bytes = <<Delta.magic()::32, 0x52, 0::64, 1 <<< 62::16>>
      assert {:ok, _} = Delta.decode(<<Delta.magic()::32, 0x53, 0::64, 1 <<< 30::32, 0>>)
      assert {:error, _} = Delta.decode(bytes)

      huge_copy = <<Delta.magic()::32, 0x54, 0::64, 1 <<< 62::64, 0>>
      assert {:ok, delta} = Delta.decode(huge_copy)
      assert Rexd.patch("abc", delta) == {:error, {:copy_out_of_range, 0, 1 <<< 62}}

      assert Rexd.patch(:binary.copy("a", 100), delta, max_size: 10) ==
               {:error, {:copy_out_of_range, 0, 1 <<< 62}}

      error =
        assert_raise StreamError, fn ->
          reader("abc") |> Rexd.Stream.patch([huge_copy]) |> Enum.to_list()
        end

      assert error.reason == {:copy_out_of_range, 0, 1 <<< 62}
    end
  end

  # -- misbehaving basis reader ---------------------------------------------------

  describe "streaming patch with a basis reader that" do
    defp patch_with_reader(read) do
      delta = <<Delta.magic()::32, 0x45, 0, 4, 0>>
      read |> Rexd.Stream.patch([delta]) |> Enum.join()
    end

    test "returns more bytes than asked" do
      error =
        assert_raise StreamError, fn ->
          patch_with_reader(fn _, len -> :binary.copy("x", len + 1) end)
        end

      assert error.reason == {:copy_out_of_range, 0, 4}
    end

    test "returns nil" do
      error = assert_raise StreamError, fn -> patch_with_reader(fn _, _ -> nil end) end
      assert error.reason == {:copy_out_of_range, 0, 4}
    end

    test "returns iodata instead of a binary" do
      error = assert_raise StreamError, fn -> patch_with_reader(fn _, _ -> ["ab", "cd"] end) end
      assert error.reason == {:copy_out_of_range, 0, 4}
    end

    test "returns exactly the bytes asked" do
      assert patch_with_reader(fn _, len -> :binary.copy("y", len) end) == "yyyy"
    end
  end
end
