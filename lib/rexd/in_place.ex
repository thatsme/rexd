defmodule Rexd.InPlace do
  @moduledoc """
  In-place patching: rebuilding the new version inside the storage that holds
  the basis, without a second copy, following Rasch and Burns, *In-Place Rsync*
  (USENIX 2003).

  A delta lists its commands in output order, and output positions follow
  from the command lengths. Applied in that order over the basis itself, a
  copy may read bytes that an earlier command has already overwritten. Copies
  are therefore applied in a dependency order instead: copy *i* must run
  before copy *j* when *i* reads bytes that *j* writes. Literal commands read
  nothing from the basis and are written last.

  Dependencies can form cycles, for example two blocks that swap places. No
  order satisfies a cycle, so the sender breaks each one by turning a copy on
  it into a literal carrying the same bytes, choosing the shortest copy on the
  cycle. The result is an ordinary delta: `rdiff patch` and `Rexd.patch/3`
  apply it as usual, and `patch/4` can apply it in place.

    * **Sender:** `make_safe/2`, or `Rexd.delta(signature, new, in_place: true)`.
    * **Receiver:** `patch/4`, with functions that read and write the storage.

  A copy that overlaps its own destination is applied in the direction that
  never reads a byte after writing it, like `memmove`.

  ## Interruption

  In-place patching overwrites the basis. If it stops part-way, through a
  crash or a failing write function, the storage holds a mixture of both
  versions and neither can be rebuilt from it. Use it where the new version
  can be obtained again in full, or where the storage offers its own
  journaling.

  ## Cost

  The dependency order is computed from the copy commands alone, in
  O(c log c) time for c copies, whatever their read ranges; a hostile delta
  cannot make it quadratic. The receiver holds the command list, including
  literal data, in memory.
  """

  alias Rexd.Delta

  @piece 65_536

  @typedoc "Reads `length` bytes of the storage starting at `offset`."
  @type read_fun :: (non_neg_integer(), pos_integer() -> binary())

  @typedoc "Writes `data` into the storage starting at `offset`."
  @type write_fun :: (non_neg_integer(), binary() -> term())

  @typedoc "Reasons `patch/4` can fail. Nothing has been written when they are returned."
  @type error ::
          {:copy_out_of_range, non_neg_integer(), non_neg_integer()}
          | :not_in_place_safe

  # -- sender -------------------------------------------------------------------

  @doc """
  Returns an equivalent delta that `patch/4` can apply in place.

  Copies that close a dependency cycle are replaced by literals holding the
  same bytes, read from `new`: the new version as a binary, or a function
  `fn offset, length -> binary end` reading it. On each cycle the shortest
  copy is converted, the earliest in output order among equals. The rebuilt
  data is unchanged.

      iex> basis = "AAAAAAAA" <> "BBBBBBBBBBBB"
      iex> new = "BBBBBBBBBBBB" <> "AAAAAAAA"
      iex> swapped = %Rexd.Delta{commands: [{:copy, 8, 12}, {:copy, 0, 8}]}
      iex> safe = Rexd.InPlace.make_safe(swapped, new)
      iex> safe.commands
      [{:copy, 8, 12}, {:literal, "AAAAAAAA"}]
      iex> Rexd.patch(basis, safe)
      {:ok, "BBBBBBBBBBBBAAAAAAAA"}
  """
  @spec make_safe(Delta.t(), binary() | read_fun()) :: Delta.t()
  def make_safe(%Delta{commands: commands}, new) when is_binary(new) or is_function(new, 2) do
    {copies, _literals} = layout(commands)
    %{converted: converted} = traverse(copies, :convert)
    %Delta{commands: rewrite(commands, converted, reader(new))}
  end

  defp reader(new) when is_binary(new), do: fn offset, len -> binary_part(new, offset, len) end
  defp reader(read), do: read

  # Replaces converted copies by literals and merges adjacent literals.
  defp rewrite(commands, converted, read) do
    commands
    |> Enum.map_reduce({0, 0}, fn command, {output_pos, copy_index} ->
      replaced = replace(command, output_pos, copy_index, converted, read)
      {replaced, {output_pos + command_len(command), copy_index + copy_count(command)}}
    end)
    |> elem(0)
    |> merge_literals([])
  end

  defp replace({:copy, _offset, len} = copy, output_pos, index, converted, read) do
    case converted do
      %{^index => true} -> {:literal, read.(output_pos, len)}
      _ -> copy
    end
  end

  defp replace(literal, _output_pos, _index, _converted, _read), do: literal

  defp merge_literals([{:literal, a}, {:literal, b} | rest], acc),
    do: merge_literals([{:literal, a <> b} | rest], acc)

  defp merge_literals([command | rest], acc), do: merge_literals(rest, [command | acc])
  defp merge_literals([], acc), do: Enum.reverse(acc)

  defp command_len({:literal, data}), do: byte_size(data)
  defp command_len({:copy, _offset, len}), do: len

  # Zero-length copies are not part of the layout, so they are not counted.
  defp copy_count({:copy, _offset, 0}), do: 0
  defp copy_count({:copy, _offset, _len}), do: 1
  defp copy_count({:literal, _data}), do: 0

  # -- receiver -----------------------------------------------------------------

  @doc """
  Applies `delta` to storage that holds the basis, overwriting it with the new
  version.

  `basis_size` is the size of the basis in the storage. `read` and `write`
  access the storage, reading and writing at most 64 KiB at a time. On success
  returns `{:ok, new_size}`; when the new version is shorter than the basis,
  the caller truncates the storage to `new_size`.

  Everything that can be checked is checked before the first write: every
  copy must lie inside the basis, and the copies must have a dependency order
  (the delta was produced by `make_safe/2` or has no cycles to begin with).

      iex> basis = "0123456789"
      iex> new = "456789" <> "0123"
      iex> sig = Rexd.signature(basis, block_len: 2)
      iex> delta = Rexd.delta(sig, new, in_place: true)
      iex> {:ok, storage} = Agent.start_link(fn -> basis end)
      iex> read = fn offset, len -> Agent.get(storage, &binary_part(&1, offset, len)) end
      iex> write = fn offset, data ->
      ...>   Agent.update(storage, fn bin ->
      ...>     <<head::binary-size(offset), _::binary-size(byte_size(data)), tail::binary>> = bin
      ...>     head <> data <> tail
      ...>   end)
      ...> end
      iex> Rexd.InPlace.patch(delta, byte_size(basis), read, write)
      {:ok, 10}
      iex> Agent.get(storage, & &1)
      "4567890123"
  """
  @spec patch(Delta.t(), non_neg_integer(), read_fun(), write_fun()) ::
          {:ok, non_neg_integer()} | {:error, error()}
  def patch(%Delta{commands: commands}, basis_size, read, write)
      when is_integer(basis_size) and basis_size >= 0 and is_function(read, 2) and
             is_function(write, 2) do
    {copies, literals} = layout(commands)

    with :ok <- check_ranges(copies, basis_size),
         {:ok, order} <- dependency_order(copies) do
      Enum.each(order, &apply_copy(elem(copies, &1), read, write))
      Enum.each(literals, fn {output_pos, data} -> write_pieces(output_pos, data, write) end)
      {:ok, output_size(copies, literals)}
    end
  end

  defp check_ranges(copies, basis_size) do
    case Enum.find(Tuple.to_list(copies), fn {src, len, _dst} -> src + len > basis_size end) do
      nil -> :ok
      {src, len, _dst} -> {:error, {:copy_out_of_range, src, len}}
    end
  end

  defp dependency_order(copies) do
    case traverse(copies, :reject) do
      %{cycle?: true} -> {:error, :not_in_place_safe}
      %{order: order} -> {:ok, order}
    end
  end

  defp output_size(copies, literals) do
    copy_end = copies |> Tuple.to_list() |> Enum.map(fn {_src, len, dst} -> dst + len end)
    literal_end = Enum.map(literals, fn {dst, data} -> dst + byte_size(data) end)
    Enum.max(copy_end ++ literal_end, fn -> 0 end)
  end

  # Moves bytes in pieces, in the direction that never reads a byte after it
  # has been overwritten when source and destination overlap.
  defp apply_copy({same, _len, same}, _read, _write), do: :ok

  defp apply_copy({src, len, dst}, read, write) when dst < src,
    do: for(offset <- piece_offsets(len), do: move(src, dst, offset, len, read, write))

  defp apply_copy({src, len, dst}, read, write),
    do:
      for(
        offset <- Enum.reverse(piece_offsets(len)),
        do: move(src, dst, offset, len, read, write)
      )

  defp piece_offsets(len), do: Enum.to_list(0..(len - 1)//@piece)

  defp move(src, dst, offset, len, read, write) do
    size = min(@piece, len - offset)
    write.(dst + offset, checked_read(read.(src + offset, size), src + offset, size))
  end

  defp checked_read(data, _offset, size) when is_binary(data) and byte_size(data) == size,
    do: data

  defp checked_read(_data, offset, size),
    do:
      raise(
        ArgumentError,
        "read function returned the wrong data for #{size} bytes at offset #{offset}"
      )

  defp write_pieces(pos, data, write) when byte_size(data) > @piece do
    <<piece::binary-size(@piece), rest::binary>> = data
    write.(pos, piece)
    write_pieces(pos + @piece, rest, write)
  end

  defp write_pieces(pos, data, write) do
    write.(pos, data)
    :ok
  end

  # -- layout -------------------------------------------------------------------

  # Output positions of every command. Copies become {src, len, dst} in a
  # tuple indexed in output order; literals become {dst, data}. Zero-length
  # commands are dropped.
  defp layout(commands) do
    {copies, literals, _pos} =
      Enum.reduce(commands, {[], [], 0}, fn
        {:copy, _src, 0}, acc ->
          acc

        {:literal, <<>>}, acc ->
          acc

        {:copy, src, len}, {copies, literals, pos} ->
          {[{src, len, pos} | copies], literals, pos + len}

        {:literal, data}, {copies, literals, pos} ->
          {copies, [{pos, data} | literals], pos + byte_size(data)}
      end)

    {copies |> Enum.reverse() |> List.to_tuple(), Enum.reverse(literals)}
  end

  # -- dependency traversal -------------------------------------------------------

  # Depth-first search over the copy graph, where copy i precedes copy j when i
  # reads bytes j writes. Destinations are disjoint and in increasing order, so
  # the copies whose destination overlaps a read range form a contiguous index
  # range, found by binary search.
  #
  # Finished and converted copies are skipped through `skip`, a next-pointer
  # structure with path compression, so a range is never scanned twice past
  # nodes that are already done.
  #
  # policy :reject stops at the first cycle; policy :convert removes the
  # shortest copy on each cycle and continues.
  defp traverse(copies, policy) do
    state = %{
      copies: copies,
      count: tuple_size(copies),
      policy: policy,
      skip: %{},
      on_path: %{},
      order: [],
      converted: %{},
      cycle?: false
    }

    visit_all(state)
  end

  defp visit_all(state) do
    case next_open(state, 0) do
      {index, state} when index < state.count -> state |> visit_root(index) |> continue_all()
      {_past_end, state} -> state
    end
  end

  defp visit_root(state, index) do
    case visit(state, index, []) do
      {:ok, state} -> state
      {:cycle, state} -> state
      {:unwind, _target, state} -> state
    end
  end

  defp continue_all(%{cycle?: true, policy: :reject} = state), do: state
  defp continue_all(state), do: visit_all(state)

  # Returns {:ok, state} once `index` is finished or converted,
  # {:unwind, target, state} while unwinding towards a converted ancestor, or
  # {:cycle, state} when rejecting.
  defp visit(state, index, path) do
    state = %{state | on_path: Map.put(state.on_path, index, true)}
    {lo, hi} = neighbour_range(state.copies, elem(state.copies, index))
    {first, state} = next_open(state, lo)
    scan_neighbours(state, index, [index | path], first, hi)
  end

  defp scan_neighbours(state, index, _path, next, hi) when next > hi,
    do: {:ok, finish(state, index)}

  defp scan_neighbours(state, index, path, index, hi) do
    {next, state} = next_open(state, index + 1)
    scan_neighbours(state, index, path, next, hi)
  end

  defp scan_neighbours(state, index, path, next, hi) do
    case state.on_path do
      %{^next => true} -> close_cycle(state, index, path, next)
      _ -> descend(state, index, path, next, hi)
    end
  end

  defp descend(state, index, path, next, hi) do
    case visit(state, next, path) do
      {:ok, state} ->
        {following, state} = next_open(state, next + 1)
        scan_neighbours(state, index, path, following, hi)

      {:unwind, ^index, state} ->
        {:ok, state}

      {:unwind, target, state} ->
        {:unwind, target, %{state | on_path: Map.delete(state.on_path, index)}}

      {:cycle, state} ->
        {:cycle, state}
    end
  end

  defp close_cycle(%{policy: :reject} = state, _index, _path, _back_to),
    do: {:cycle, %{state | cycle?: true}}

  defp close_cycle(state, index, path, back_to) do
    cycle = take_until(path, back_to, [])
    victim = Enum.min_by(cycle, fn node -> {elem(elem(state.copies, node), 1), node} end)

    state = %{
      state
      | converted: Map.put(state.converted, victim, true),
        on_path: Map.delete(state.on_path, victim),
        skip: Map.put(state.skip, victim, victim + 1)
    }

    unwind_from(state, index, victim)
  end

  defp unwind_from(state, index, index), do: {:ok, state}

  defp unwind_from(state, index, victim),
    do: {:unwind, victim, %{state | on_path: Map.delete(state.on_path, index)}}

  defp take_until([node | _rest], node, acc), do: [node | acc]
  defp take_until([node | rest], target, acc), do: take_until(rest, target, [node | acc])

  defp finish(state, index) do
    %{
      state
      | on_path: Map.delete(state.on_path, index),
        skip: Map.put(state.skip, index, index + 1),
        order: [index | state.order]
    }
  end

  # Smallest index >= `from` that is neither finished nor converted.
  defp next_open(state, from) do
    {root, skip} = find(state.skip, from)
    {root, %{state | skip: skip}}
  end

  defp find(skip, index) do
    case skip do
      %{^index => next} ->
        {root, skip} = find(skip, next)
        {root, Map.put(skip, index, root)}

      _ ->
        {index, skip}
    end
  end

  # Index range of copies whose destination overlaps [src, src + len).
  defp neighbour_range(copies, {src, len, _dst}) do
    lo = first_index(copies, 0, tuple_size(copies), fn {_s, l, d} -> d + l > src end)
    hi = first_index(copies, 0, tuple_size(copies), fn {_s, _l, d} -> d >= src + len end) - 1
    {lo, hi}
  end

  # First index in [lo, hi) whose element satisfies the monotone predicate,
  # or hi when none does.
  defp first_index(_copies, lo, lo, _pred), do: lo

  defp first_index(copies, lo, hi, pred) do
    mid = div(lo + hi, 2)

    case pred.(elem(copies, mid)) do
      true -> first_index(copies, lo, mid, pred)
      false -> first_index(copies, mid + 1, hi, pred)
    end
  end
end
