defmodule Rexd.InPlaceTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Rexd.{Delta, InPlace}
  alias Rexd.Test.Oracle

  doctest InPlace

  # -- storage simulation -------------------------------------------------------

  # A mutable byte store backed by the process dictionary, so that reads see
  # earlier writes exactly as a file would. Writes are recorded for inspection.
  defp storage(initial) do
    key = make_ref()
    Process.put(key, initial)
    Process.put({key, :writes}, 0)

    read = fn offset, len ->
      data = Process.get(key)
      binary_part(data, offset, len)
    end

    write = fn offset, bytes ->
      data = Process.get(key)
      padded = data <> :binary.copy(<<0>>, max(0, offset + byte_size(bytes) - byte_size(data)))
      <<head::binary-size(offset), _::binary-size(byte_size(bytes)), tail::binary>> = padded
      Process.put(key, head <> bytes <> tail)
      Process.put({key, :writes}, Process.get({key, :writes}) + 1)
    end

    contents = fn size -> binary_part(Process.get(key), 0, size) end
    writes = fn -> Process.get({key, :writes}) end
    %{read: read, write: write, contents: contents, writes: writes}
  end

  defp patch_in_place(basis, delta) do
    store = storage(basis)

    case InPlace.patch(delta, byte_size(basis), store.read, store.write) do
      {:ok, size} -> {:ok, store.contents.(size)}
      error -> error
    end
  end

  # -- generators -----------------------------------------------------------------

  defp edit do
    one_of([
      tuple({constant(:insert), integer(0..100_000), binary(min_length: 1, max_length: 100)}),
      tuple({constant(:delete), integer(0..100_000), integer(1..300)}),
      tuple({constant(:move), integer(0..100_000), integer(1..400), integer(0..100_000)}),
      tuple({constant(:swap), integer(0..100_000), integer(1..300)})
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

  defp apply_edit(data, {:move, from, len, to}) do
    from = rem(from, byte_size(data) + 1)
    len = min(len, byte_size(data) - from)
    <<a::binary-size(from), moved::binary-size(len), b::binary>> = data
    rest = a <> b
    to = rem(to, byte_size(rest) + 1)
    <<c::binary-size(to), d::binary>> = rest
    c <> moved <> d
  end

  # Swaps two adjacent regions of `len` bytes.
  defp apply_edit(data, {:swap, at, len}) when byte_size(data) >= 2 * len do
    at = rem(at, byte_size(data) - 2 * len + 1)
    <<a::binary-size(at), x::binary-size(len), y::binary-size(len), b::binary>> = data
    a <> y <> x <> b
  end

  defp apply_edit(data, {:swap, _at, _len}), do: data

  # Arbitrary valid delta over a basis: copies anywhere inside it, literals in between.
  defp raw_delta(basis_size) do
    command =
      one_of([
        map(binary(min_length: 1, max_length: 50), &{:literal, &1}),
        bind(integer(0..max(basis_size - 1, 0)), fn offset ->
          map(integer(1..max(basis_size - offset, 1)), &{:copy, offset, &1})
        end)
      ])

    map(list_of(command, max_length: 30), fn commands ->
      %Delta{commands: Enum.reject(commands, &(match?({:copy, _, _}, &1) and basis_size == 0))}
    end)
  end

  # -- properties -----------------------------------------------------------------

  property "in-place deltas from the search rebuild the new data in place" do
    check all basis <- binary(min_length: 0, max_length: 4000),
              edits <- list_of(edit(), max_length: 5),
              block_len <- member_of([1, 4, 16, 64, 256]) do
      new = Enum.reduce(edits, basis, &apply_edit(&2, &1))
      delta = Rexd.delta(Rexd.signature(basis, block_len: block_len), new, in_place: true)

      assert Rexd.patch(basis, delta) == {:ok, new}
      assert patch_in_place(basis, delta) == {:ok, new}
    end
  end

  property "make_safe/2 on arbitrary deltas keeps the output and makes it applicable in place" do
    check all basis <- binary(min_length: 1, max_length: 3000),
              delta <- raw_delta(byte_size(basis)),
              max_runs: 500 do
      {:ok, new} = Rexd.patch(basis, delta)
      safe = InPlace.make_safe(delta, new)

      assert Rexd.patch(basis, safe) == {:ok, new}
      assert patch_in_place(basis, safe) == {:ok, new}
      assert InPlace.make_safe(delta, fn offset, len -> binary_part(new, offset, len) end) == safe
    end
  end

  property "make_safe/2 never adds literals to a delta that is already safe" do
    check all basis <- binary(min_length: 1, max_length: 3000),
              delta <- raw_delta(byte_size(basis)) do
      {:ok, new} = Rexd.patch(basis, delta)
      safe = InPlace.make_safe(delta, new)
      assert InPlace.make_safe(safe, new) == safe
    end
  end

  # -- specific shapes -------------------------------------------------------------

  describe "cycles" do
    test "a swap of two blocks converts the shorter copy" do
      basis = String.duplicate("a", 10) <> String.duplicate("b", 30)
      new = String.duplicate("b", 30) <> String.duplicate("a", 10)
      delta = %Delta{commands: [{:copy, 10, 30}, {:copy, 0, 10}]}

      assert InPlace.make_safe(delta, new).commands == [
               {:copy, 10, 30},
               {:literal, String.duplicate("a", 10)}
             ]
    end

    test "a rotation of four blocks converts exactly one" do
      blocks = for c <- ~c"ABCD", do: :binary.copy(<<c>>, 16)
      basis = Enum.join(blocks)
      [a, b, c, d] = blocks
      new = d <> a <> b <> c
      delta = Rexd.delta(Rexd.signature(basis, block_len: 16), new, in_place: true)

      assert Enum.count(delta.commands, &match?({:literal, _}, &1)) == 1
      assert Delta.stats(delta).literal_bytes == 16
      assert patch_in_place(basis, delta) == {:ok, new}
    end

    test "an insertion at the start needs no conversion" do
      basis = :crypto.strong_rand_bytes(10_000)
      new = "inserted" <> basis
      delta = Rexd.delta(Rexd.signature(basis, block_len: 64), new, in_place: true)

      assert delta.commands == [{:literal, "inserted"}, {:copy, 0, 10_000}]
      assert patch_in_place(basis, delta) == {:ok, new}
    end

    test "a deletion at the start needs no conversion" do
      basis = :crypto.strong_rand_bytes(10_000)
      <<_::binary-size(1000), new::binary>> = basis
      delta = Rexd.delta(Rexd.signature(basis, block_len: 64), new, in_place: true)

      assert Delta.stats(delta).literal_bytes <= 64
      assert patch_in_place(basis, delta) == {:ok, new}
    end

    test "copies larger than the 64 KiB write piece, overlapping their destination" do
      basis = :crypto.strong_rand_bytes(300_000)
      <<head::binary-size(1000), tail::binary>> = basis

      for new <- ["xyz" <> basis, tail <> head, binary_part(basis, 70_000, 200_000)] do
        delta = Rexd.delta(Rexd.signature(basis, block_len: 1024), new, in_place: true)
        assert patch_in_place(basis, delta) == {:ok, new}
      end
    end
  end

  describe "receiver checks, before any write" do
    test "a delta with a dependency cycle is rejected" do
      basis = String.duplicate("a", 8) <> String.duplicate("b", 8)
      store = storage(basis)
      unsafe = %Delta{commands: [{:copy, 8, 8}, {:copy, 0, 8}]}

      assert InPlace.patch(unsafe, 16, store.read, store.write) == {:error, :not_in_place_safe}
      assert store.writes.() == 0
      assert store.contents.(16) == basis
    end

    test "a copy outside the basis is rejected" do
      store = storage("abcdef")
      delta = %Delta{commands: [{:literal, "xx"}, {:copy, 4, 5}]}

      assert InPlace.patch(delta, 6, store.read, store.write) ==
               {:error, {:copy_out_of_range, 4, 5}}

      assert store.writes.() == 0
    end

    test "empty delta" do
      store = storage("abc")
      assert InPlace.patch(%Delta{commands: []}, 3, store.read, store.write) == {:ok, 0}
    end

    test "a read function returning the wrong size raises" do
      delta = %Delta{commands: [{:copy, 2, 2}]}

      assert_raise ArgumentError, fn ->
        InPlace.patch(delta, 4, fn _, _ -> "x" end, fn _, _ -> :ok end)
      end
    end
  end

  describe "hostile dependency graphs" do
    # `big` long copies each read the region written by `small` one-byte
    # copies, giving big * small dependency edges.
    defp dense_delta(big, small) do
      big_len = small
      output_end = big * big_len + small

      bigs = for _ <- 1..big, do: {:copy, big * big_len, small}
      smalls = for j <- 1..small, do: {:copy, output_end + j, 1}
      {%Delta{commands: bigs ++ smalls}, output_end + small + 1}
    end

    test "400 million dependency edges are ordered in near-linear time" do
      {delta, basis_size} = dense_delta(20_000, 20_000)
      store = %{read: fn _, len -> :binary.copy(<<0>>, len) end, write: fn _, _ -> :ok end}

      {micros, result} =
        :timer.tc(fn -> InPlace.patch(delta, basis_size, store.read, store.write) end)

      assert {:ok, _size} = result
      assert micros < 5_000_000
    end

    test "a large cyclic delta is rejected in linear time" do
      commands = for i <- 0..49_999, do: {:copy, rem(i + 1, 50_000), 1}

      {micros, result} =
        :timer.tc(fn ->
          InPlace.patch(
            %Delta{commands: commands},
            50_000,
            fn _, l -> <<0::size(l * 8)>> end,
            fn _, _ -> :ok end
          )
        end)

      assert result == {:error, :not_in_place_safe}
      assert micros < 5_000_000
    end

    test "breaking many cycles stays fast" do
      pairs = 20_000
      commands = for i <- 0..(pairs - 1), c <- [{:copy, 2 * i + 1, 1}, {:copy, 2 * i, 1}], do: c
      new = :binary.copy(<<7>>, 2 * pairs)
      {micros, safe} = :timer.tc(fn -> InPlace.make_safe(%Delta{commands: commands}, new) end)
      assert Delta.stats(safe).literal_commands == pairs
      assert micros < 5_000_000
    end
  end

  describe "oracle" do
    @describetag :rdiff
    @describetag :tmp_dir

    property "rdiff patch applies in-place deltas", %{tmp_dir: dir} do
      check all basis <- binary(max_length: 3000),
                edits <- list_of(edit(), max_length: 4),
                max_runs: 40 do
        new = Enum.reduce(edits, basis, &apply_edit(&2, &1))
        delta = Rexd.delta(Rexd.signature(basis, block_len: 32), new, in_place: true)
        encoded = delta |> Delta.encode() |> IO.iodata_to_binary()
        assert Oracle.rdiff_patch(basis, encoded, dir) == new
      end
    end
  end
end
