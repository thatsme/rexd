defmodule Rexd.Stream do
  @moduledoc """
  Streaming signature, delta and patch.

  Each function takes an enumerable of binaries, split at arbitrary
  boundaries, and returns a lazy enumerable of binaries. Concatenated, the
  output is the librsync wire format (`signature/2`, `delta/2`) or the
  rebuilt data (`patch/3`). Nothing is read until the result is consumed.

  ## Memory

    * `signature/2` holds less than one block of input.
    * `delta/2` holds the signature, one block, the current input chunk
      (small chunks are grouped up to 64 KiB, larger ones are used as given),
      and the unmatched bytes not yet emitted. Those are emitted as a literal
      command once they reach 64 KiB at the end of an input chunk.
    * `patch/3` holds a partial command header. Literal data is passed
      through as it arrives, and copies are read from the basis in pieces of
      at most 64 KiB.

  ## Differences from the whole-binary functions

  `signature/2` produces exactly the bytes of `Rexd.Signature.encode/1`.
  `delta/2` finds the same matches as `Rexd.delta/2`, but may split a long
  unmatched run into several literal commands, as librsync does; the rebuilt
  output is identical.

  ## Errors

  Invalid options raise `ArgumentError` when the function is called. Invalid
  input can only be detected while the stream is consumed, so it raises
  `Rexd.StreamError` then, with the same reason terms as the tuple-returning
  functions.
  """

  alias Rexd.{Delta, Patch, Signature, StreamError}
  alias Rexd.Delta.{Search, Stats}

  @chunk_size 65_536
  @max_literal 65_536
  @copy_piece 65_536
  @delta_magic Delta.magic()

  @typedoc "Reads `length` bytes of the basis starting at `offset`."
  @type basis_fun :: (non_neg_integer(), pos_integer() -> binary())

  # -- signature -----------------------------------------------------------------

  @doc """
  Streams the encoded signature of the basis read from `enumerable`.

  Takes the options of `Rexd.signature/2`.

      iex> basis = String.duplicate("abcdefgh", 100)
      iex> streamed = ["abcdefgh" |> String.duplicate(40), String.duplicate("abcdefgh", 60)]
      iex> streamed |> Rexd.Stream.signature(block_len: 64) |> Enum.join() ==
      ...>   basis |> Rexd.signature(block_len: 64) |> Rexd.Signature.encode() |> IO.iodata_to_binary()
      true
  """
  @spec signature(Enumerable.t(), keyword()) :: Enumerable.t()
  def signature(enumerable, opts \\ []) do
    {block_len, strong_sum_len} = Signature.options!(opts)
    sig = %Signature{block_len: block_len, strong_sum_len: strong_sum_len}

    blocks =
      enumerable
      |> rechunk(block_len)
      |> Stream.transform(
        fn -> <<>> end,
        &sign_chunk(&1, &2, sig),
        &sign_remainder(&1, sig),
        fn _remainder -> :ok end
      )

    Stream.concat([Signature.encode_header(sig)], blocks)
  end

  # `remainder` is shorter than one block; only whole blocks are signed here.
  defp sign_chunk(chunk, remainder, sig) do
    data = remainder <> chunk
    whole = div(byte_size(data), sig.block_len) * sig.block_len
    <<blocks::binary-size(whole), remainder::binary>> = data
    {encoded_blocks(blocks, sig), remainder}
  end

  defp sign_remainder(remainder, sig), do: {encoded_blocks(remainder, sig), <<>>}

  defp encoded_blocks(<<>>, _sig), do: []

  defp encoded_blocks(data, %Signature{block_len: block_len, strong_sum_len: strong_sum_len}) do
    sig = Signature.compute(data, block_len: block_len, strong_sum_len: strong_sum_len)
    [IO.iodata_to_binary(Signature.encode_blocks(sig))]
  end

  # -- delta ---------------------------------------------------------------------

  @doc """
  Streams the encoded delta from the basis described by `signature` to the
  new data read from `enumerable`.

  ## Options

    * `:on_stats` - a function called with `Rexd.Delta.Stats` once the last
      command has been produced, before the end marker is emitted.

      iex> basis = String.duplicate("0123456789", 50)
      iex> new = ["prefix ", basis, " suffix"]
      iex> sig = Rexd.signature(basis, block_len: 16)
      iex> {:ok, delta} = sig |> Rexd.Stream.delta(new) |> Enum.join() |> Rexd.Delta.decode()
      iex> Rexd.patch(basis, delta) == {:ok, IO.iodata_to_binary(new)}
      true
  """
  @spec delta(Signature.t(), Enumerable.t(), keyword()) :: Enumerable.t()
  def delta(%Signature{} = signature, enumerable, opts \\ []) do
    on_stats =
      opts |> Keyword.validate!(on_stats: nil) |> Keyword.fetch!(:on_stats) |> valid_on_stats!()

    commands =
      enumerable
      |> rechunk(@chunk_size)
      |> Stream.transform(
        fn -> {Search.new(signature, @max_literal), %Stats{}} end,
        &delta_chunk/2,
        &delta_end(&1, on_stats),
        fn _state -> :ok end
      )

    Stream.concat([Delta.encode_header()], commands)
  end

  defp valid_on_stats!(nil), do: nil
  defp valid_on_stats!(fun) when is_function(fun, 1), do: fun

  defp valid_on_stats!(other),
    do: raise(ArgumentError, "on_stats must be a 1-arity function, got: #{inspect(other)}")

  defp delta_chunk(chunk, {search, stats}) do
    {commands, search} = Search.feed(search, chunk)
    {encoded_commands(commands), {search, Stats.add_commands(stats, commands)}}
  end

  defp delta_end({search, stats}, on_stats) do
    {commands, counters} = Search.finish(search)
    stats = stats |> struct(counters) |> Stats.add_commands(commands)
    report_stats(on_stats, stats)
    {encoded_commands(commands) ++ [Delta.encode_end()], {search, stats}}
  end

  defp report_stats(nil, _stats), do: :ok
  defp report_stats(on_stats, stats), do: on_stats.(stats)

  defp encoded_commands([]), do: []
  defp encoded_commands(commands), do: [IO.iodata_to_binary(Delta.encode_commands(commands))]

  # -- patch ---------------------------------------------------------------------

  @doc """
  Streams the data rebuilt by applying the encoded delta read from
  `enumerable` to a basis.

  The basis is read through `basis_fun`, called as `basis_fun.(offset, length)`
  with `length` of at most 64 KiB. It must return exactly `length` bytes, or a
  shorter binary when the range extends past the end of the basis. For a file,
  `fn offset, length -> :file.pread(io_device, offset, length) end` wrapped to
  return the data (or `<<>>` on `:eof`) is enough.

  Takes the options of `Rexd.patch/3`. Raises `Rexd.StreamError` while
  consumed on an invalid delta, a copy past the end of the basis, or output
  beyond `:max_size`.

      iex> basis = "the quick brown fox"
      iex> sig = Rexd.signature(basis, block_len: 4)
      iex> encoded = sig |> Rexd.Stream.delta(["the quick red fox"]) |> Enum.join()
      iex> read = fn offset, length -> binary_part(basis, offset, min(length, byte_size(basis) - offset)) end
      iex> read |> Rexd.Stream.patch([encoded]) |> Enum.join()
      "the quick red fox"
  """
  @spec patch(basis_fun(), Enumerable.t(), keyword()) :: Enumerable.t()
  def patch(basis_fun, enumerable, opts \\ []) when is_function(basis_fun, 2) do
    max_size = Patch.options!(opts)

    Stream.transform(
      enumerable,
      fn -> %{phase: :magic, buffer: <<>>, produced: 0, max_size: max_size, basis: basis_fun} end,
      &patch_chunk/2,
      &patch_end/1,
      fn _state -> :ok end
    )
  end

  defp patch_chunk(chunk, state) when is_binary(chunk) do
    {segments, state} = patch_step(%{state | buffer: state.buffer <> chunk}, [])
    {Stream.concat(Enum.reverse(segments)), state}
  end

  defp patch_end(%{phase: :done} = state), do: {[], state}
  defp patch_end(%{phase: :magic}), do: fail!(:truncated_header)
  defp patch_end(%{phase: :commands, buffer: <<>>}), do: fail!(:missing_end)
  defp patch_end(_state), do: fail!(:truncated)

  # Consumes as much of the buffer as possible. `segments` collects, in
  # reverse, enumerables of output binaries: literal data as a one-element
  # list, copies as a lazy stream of basis reads.
  defp patch_step(%{phase: :magic, buffer: <<@delta_magic::32, rest::binary>>} = state, segments),
    do: patch_step(%{state | phase: :commands, buffer: rest}, segments)

  defp patch_step(%{phase: :magic, buffer: <<magic::32, _::binary>>}, _segments),
    do: fail!({:bad_magic, magic})

  defp patch_step(%{phase: :magic} = state, segments), do: {segments, state}

  defp patch_step(%{phase: :commands, buffer: buffer} = state, segments),
    do: patch_command(Delta.next_command(buffer), state, segments)

  defp patch_step(%{phase: {:literal, _remaining}, buffer: <<>>} = state, segments),
    do: {segments, state}

  defp patch_step(%{phase: {:literal, remaining}, buffer: buffer} = state, segments)
       when byte_size(buffer) >= remaining do
    <<data::binary-size(remaining), rest::binary>> = buffer
    patch_step(%{state | phase: :commands, buffer: rest}, [[data] | segments])
  end

  defp patch_step(%{phase: {:literal, remaining}, buffer: buffer} = state, segments) do
    state = %{state | phase: {:literal, remaining - byte_size(buffer)}, buffer: <<>>}
    {[[buffer] | segments], state}
  end

  defp patch_step(%{phase: :done, buffer: <<>>} = state, segments), do: {segments, state}
  defp patch_step(%{phase: :done}, _segments), do: fail!(:trailing_data)

  defp patch_command({:ok, :end, rest}, state, segments),
    do: patch_step(%{state | phase: :done, buffer: rest}, segments)

  defp patch_command({:ok, {:literal_header, len}, rest}, state, segments) do
    state = count_output!(state, len)
    patch_step(%{state | phase: {:literal, len}, buffer: rest}, segments)
  end

  defp patch_command({:ok, {:copy, offset, len}, rest}, state, segments) do
    state = count_output!(state, len)
    patch_step(%{state | buffer: rest}, [copy_pieces(state.basis, offset, len) | segments])
  end

  defp patch_command(:end_of_input, state, segments), do: {segments, state}
  defp patch_command(:incomplete, state, segments), do: {segments, state}
  defp patch_command({:error, reason}, _state, _segments), do: fail!(reason)

  defp count_output!(%{max_size: :infinity, produced: produced} = state, len),
    do: %{state | produced: produced + len}

  defp count_output!(%{max_size: max_size, produced: produced} = state, len)
       when produced + len <= max_size,
       do: %{state | produced: produced + len}

  defp count_output!(%{max_size: max_size, produced: produced}, len),
    do: fail!({:output_too_large, produced + len, max_size})

  defp copy_pieces(basis_fun, offset, len) do
    Stream.unfold({offset, len}, fn
      {_at, 0} ->
        nil

      {at, remaining} ->
        piece = min(remaining, @copy_piece)
        data = basis_fun.(at, piece)
        {checked_piece(data, piece, offset, len), {at + piece, remaining - piece}}
    end)
  end

  defp checked_piece(data, piece, _offset, _len)
       when is_binary(data) and byte_size(data) == piece,
       do: data

  defp checked_piece(_data, _piece, offset, len), do: fail!({:copy_out_of_range, offset, len})

  defp fail!(reason), do: raise(StreamError, reason: reason)

  # -- input ---------------------------------------------------------------------

  # Groups small input chunks so that each emitted binary holds at least
  # `min_size` bytes (the last one excepted); large chunks pass through.
  defp rechunk(enumerable, min_size) do
    Stream.transform(
      enumerable,
      fn -> {[], 0} end,
      fn chunk, {pending, size} when is_binary(chunk) ->
        gathered([pending, chunk], size + byte_size(chunk), min_size)
      end,
      fn {pending, _size} -> {[IO.iodata_to_binary(pending)], {[], 0}} end,
      fn _pending -> :ok end
    )
  end

  defp gathered(pending, size, min_size) when size >= min_size,
    do: {[IO.iodata_to_binary(pending)], {[], 0}}

  defp gathered(pending, size, _min_size), do: {[], {pending, size}}
end
