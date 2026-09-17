defmodule Rexd.Delta.Search do
  @moduledoc false
  # The rsync delta search, resumable across chunks of input.
  #
  # Input arrives through feed/2 and ends with finish/1; run/2 is a single feed
  # followed by finish, so whole-binary and streaming deltas share this code.
  #
  # Phase 1 (scan): a full block_len window slides over the buffered input one
  # byte at a time. Each window is classified against the signature:
  #
  #   * miss            - weak checksum not in the index
  #   * :false_hit      - weak checksum found, strong hash matches no block
  #   * {:match, block} - a block with equal weak and strong checksums
  #
  # A match emits a copy and restarts the window right after it; anything
  # else rolls the window forward by one byte. Misses are by far the most
  # common case and are handled directly in scan/4.
  #
  # When the window reaches the end of the buffer before the input has ended,
  # the search suspends and records where it stopped: the window position and
  # its weak checksum, or nil when no window has been started there.
  #
  # Phase 2 (tail): once the input has ended and no full window fits, the
  # window shrinks from the front. Only the last basis block can be shorter
  # than block_len, so it is the only candidate.
  #
  # Between feeds, the buffer keeps only bytes from the start of the pending
  # literal onward, and a pending literal of max_literal bytes or more is
  # emitted, so memory stays bounded by max_literal + block_len + chunk size.
  #
  # Shaped for speed (see NOTES.md, "Code shaped by performance"):
  #
  #   * Misses are handled inline in scan/4 rather than through a uniform
  #     classify-then-record step, which cost two extra calls per byte.
  #   * advance/4 destructures Context once instead of using ctx.field, which
  #     compiles to a separate map match per access.

  alias Rexd.{Delta, RabinKarp, Signature}

  defmodule Context do
    @moduledoc false
    # buffer holds the input not yet fully processed; size is its byte size.
    # last_full is the final buffer position where a full window fits
    # (negative when none does); final? is true once the input has ended.
    # mult and adj are the RabinKarp constants for block_len.
    @enforce_keys [
      :buffer,
      :size,
      :final?,
      :block_len,
      :strong_sum_len,
      :index,
      :blocks,
      :block_count,
      :last_full,
      :mult,
      :adj
    ]
    defstruct @enforce_keys
  end

  defmodule Output do
    @moduledoc false
    # commands are accumulated in reverse; literal_start is the buffer offset
    # of the first byte not yet covered by a command; next_block is the block
    # that would extend the most recent copy.
    defstruct commands: [], literal_start: 0, next_block: nil, weak_hits: 0, false_weak_hits: 0
  end

  # pos and weak record where the search suspended (see above).
  @enforce_keys [:ctx, :max_literal, :out]
  defstruct [:ctx, :max_literal, :out, pos: 0, weak: nil]

  @type t :: %__MODULE__{}

  @doc false
  @spec new(Signature.t(), pos_integer() | :infinity) :: t()
  def new(%Signature{} = sig, max_literal) do
    %Signature{index: index} = sig = Signature.build_index(sig)
    {mult, adj} = RabinKarp.window(sig.block_len)

    ctx = %Context{
      buffer: <<>>,
      size: 0,
      final?: false,
      block_len: sig.block_len,
      strong_sum_len: sig.strong_sum_len,
      index: index,
      blocks: List.to_tuple(sig.blocks),
      block_count: length(sig.blocks),
      last_full: -sig.block_len,
      mult: mult,
      adj: adj
    }

    %__MODULE__{ctx: ctx, max_literal: max_literal, out: %Output{}}
  end

  @doc false
  # Appends `chunk` and searches as far as the buffered input allows. Returns
  # the commands that can no longer change, in order.
  @spec feed(t(), binary()) :: {[Delta.command()], t()}
  def feed(%__MODULE__{} = search, chunk) when is_binary(chunk) do
    search = append(search, chunk)
    {:suspended, pos, weak, out} = resume(search, search.ctx)

    out = cap_literal(out, search.ctx, pos, search.max_literal)
    {ready, out} = take_ready(out, pos)
    {ready, %{search | pos: pos, weak: weak, out: out}}
  end

  @doc false
  # Ends the input. Returns the remaining commands and the search counters.
  @spec finish(t()) :: {[Delta.command()], Delta.stats()}
  def finish(%__MODULE__{ctx: ctx} = search) do
    {:done, out} = resume(search, %{ctx | final?: true})
    {Enum.reverse(out.commands), stats(out)}
  end

  @doc false
  @spec run(Signature.t(), binary()) :: {[Delta.command()], Delta.stats()}
  def run(%Signature{} = sig, new) when is_binary(new) do
    {ready, search} = sig |> new(:infinity) |> feed(new)
    {rest, stats} = finish(search)
    {ready ++ rest, stats}
  end

  defp stats(%Output{weak_hits: hits, false_weak_hits: false_hits}),
    do: %{weak_hits: hits, false_weak_hits: false_hits}

  # -- buffering ---------------------------------------------------------------

  defp append(%__MODULE__{ctx: ctx, pos: pos, out: out} = search, chunk) do
    {buffer, dropped} = rebuffer(ctx, out.literal_start, chunk)
    size = byte_size(buffer)
    ctx = %{ctx | buffer: buffer, size: size, last_full: size - ctx.block_len}
    out = %{out | literal_start: out.literal_start - dropped}
    %{search | ctx: ctx, pos: pos - dropped, out: out}
  end

  # Bytes before literal_start are covered by emitted commands and can be
  # dropped. Dropping copies the rest, so it only happens once at least half
  # of the buffer is droppable; the total copying stays linear in the input.
  defp rebuffer(%Context{size: 0}, _droppable, chunk), do: {chunk, 0}

  defp rebuffer(%Context{buffer: buffer, size: size}, droppable, chunk)
       when droppable > 0 and droppable * 2 >= size,
       do: {binary_part(buffer, droppable, size - droppable) <> chunk, droppable}

  defp rebuffer(%Context{buffer: buffer}, _droppable, chunk), do: {buffer <> chunk, 0}

  defp resume(%__MODULE__{pos: pos, weak: nil, out: out}, ctx), do: start_window(pos, ctx, out)
  defp resume(%__MODULE__{pos: pos, weak: weak, out: out}, ctx), do: advance(pos, weak, ctx, out)

  defp cap_literal(out, _ctx, _pos, :infinity), do: out

  defp cap_literal(%Output{literal_start: start} = out, ctx, pos, max_literal)
       when pos - start >= max_literal,
       do: flush_literal(out, ctx, pos)

  defp cap_literal(out, _ctx, _pos, _max_literal), do: out

  # A copy ending exactly at the current position may still be extended by
  # the next match, so it is held back.
  defp take_ready(
         %Output{commands: [{:copy, _, _} = copy | rest], literal_start: pos} = out,
         pos
       ),
       do: {Enum.reverse(rest), %{out | commands: [copy]}}

  defp take_ready(%Output{commands: commands} = out, _pos),
    do: {Enum.reverse(commands), %{out | commands: []}}

  # -- phase 1: full windows ------------------------------------------------------

  # Per-byte hot path: keep the miss branch free of extra calls.
  defp scan(pos, weak, %Context{index: index} = ctx, out) do
    case index do
      %{^weak => candidates} -> weak_hit(pos, weak, candidates, ctx, out)
      _ -> advance(pos, weak, ctx, out)
    end
  end

  defp weak_hit(pos, weak, candidates, ctx, out) do
    strong = strong_at(ctx, pos, ctx.block_len)

    case confirm(strong, weak, candidates, ctx, out.next_block) do
      {:match, block} = result ->
        out = out |> record(result) |> emit_copy(ctx, pos, block, ctx.block_len)
        start_window(pos + ctx.block_len, ctx, out)

      :false_hit ->
        advance(pos, weak, ctx, record(out, :false_hit))
    end
  end

  # Per-byte hot path: one destructuring match instead of five ctx.field lookups.
  defp advance(pos, weak, %Context{last_full: last_full} = ctx, out) when pos < last_full do
    %Context{buffer: buffer, block_len: block_len, mult: mult, adj: adj} = ctx
    out_byte = :binary.at(buffer, pos)
    in_byte = :binary.at(buffer, pos + block_len)
    scan(pos + 1, RabinKarp.rotate(weak, out_byte, in_byte, mult, adj), ctx, out)
  end

  defp advance(pos, weak, %Context{final?: false}, out), do: {:suspended, pos, weak, out}
  defp advance(pos, weak, ctx, out), do: tail(pos + 1, drop_first(weak, ctx, pos), ctx, out)

  # Starts a fresh window at `pos`, after a match or where a previous feed
  # stopped before one could be started. Without basis blocks every byte is
  # literal, so the search skips straight to the end of the buffer.
  defp start_window(pos, %Context{block_count: 0, final?: false, size: size}, out),
    do: {:suspended, max(pos, size), nil, out}

  defp start_window(_pos, %Context{block_count: 0} = ctx, out), do: finish_output(out, ctx)

  defp start_window(pos, %Context{last_full: last_full} = ctx, out) when pos <= last_full,
    do: scan(pos, weak_at(ctx, pos, ctx.block_len), ctx, out)

  defp start_window(pos, %Context{final?: false}, out), do: {:suspended, pos, nil, out}

  defp start_window(pos, ctx, out),
    do: tail(pos, weak_at(ctx, pos, ctx.size - pos), ctx, out)

  # -- phase 2: shrinking window at the end of the input ------------------------

  defp tail(pos, _weak, %Context{size: pos} = ctx, out), do: finish_output(out, ctx)

  defp tail(pos, weak, ctx, out) do
    len = ctx.size - pos

    case classify_tail(pos, len, weak, ctx) do
      {:match, block} = result ->
        out |> record(result) |> emit_copy(ctx, pos, block, len) |> finish_output(ctx)

      result ->
        tail(pos + 1, drop_first(weak, ctx, pos), ctx, record(out, result))
    end
  end

  defp classify_tail(pos, len, weak, ctx) do
    last_block = ctx.block_count - 1

    case elem(ctx.blocks, last_block) do
      {^weak, block_strong} -> compare_strong(strong_at(ctx, pos, len), block_strong, last_block)
      _ -> :miss
    end
  end

  defp compare_strong(strong, strong, block), do: {:match, block}
  defp compare_strong(_window_strong, _block_strong, _block), do: :false_hit

  # -- matching ----------------------------------------------------------------

  # Prefer the block that extends the previous copy, so runs of identical
  # blocks (stored once in the index) coalesce into a single command.
  defp confirm(strong, weak, candidates, ctx, next_block) do
    case next_block_checksums(ctx, next_block) do
      {^weak, ^strong} -> {:match, next_block}
      _ -> candidate_match(Map.fetch(candidates, strong))
    end
  end

  defp next_block_checksums(_ctx, nil), do: nil
  defp next_block_checksums(%Context{block_count: count}, next) when next >= count, do: nil
  defp next_block_checksums(%Context{blocks: blocks}, next), do: elem(blocks, next)

  defp candidate_match({:ok, block}), do: {:match, block}
  defp candidate_match(:error), do: :false_hit

  # -- output ------------------------------------------------------------------

  defp record(out, :miss), do: out
  defp record(out, {:match, _block}), do: %{out | weak_hits: out.weak_hits + 1}

  defp record(out, :false_hit),
    do: %{out | weak_hits: out.weak_hits + 1, false_weak_hits: out.false_weak_hits + 1}

  defp emit_copy(out, ctx, pos, block, len) do
    out = flush_literal(out, ctx, pos)
    commands = add_copy(out.commands, block * ctx.block_len, len)
    %{out | commands: commands, literal_start: pos + len, next_block: block + 1}
  end

  # Commands are in reverse order: the head is the most recent command.
  defp add_copy([{:copy, prev_offset, prev_len} | rest], offset, len)
       when prev_offset + prev_len == offset,
       do: [{:copy, prev_offset, prev_len + len} | rest]

  defp add_copy(commands, offset, len), do: [{:copy, offset, len} | commands]

  defp finish_output(out, ctx), do: {:done, flush_literal(out, ctx, ctx.size)}

  defp flush_literal(%Output{literal_start: pos} = out, _ctx, pos), do: out

  defp flush_literal(%Output{literal_start: start} = out, ctx, pos) do
    literal = {:literal, binary_part(ctx.buffer, start, pos - start)}
    %{out | commands: [literal | out.commands], literal_start: pos}
  end

  # -- checksums ---------------------------------------------------------------

  defp weak_at(ctx, pos, len), do: RabinKarp.hash(binary_part(ctx.buffer, pos, len))

  defp strong_at(ctx, pos, len),
    do: Signature.strong(binary_part(ctx.buffer, pos, len), ctx.strong_sum_len)

  # Removes buffer[pos] from the front of the window buffer[pos, size).
  defp drop_first(weak, ctx, pos) do
    {mult, adj} = RabinKarp.window(ctx.size - pos - 1)
    RabinKarp.rollout(weak, :binary.at(ctx.buffer, pos), mult, adj)
  end
end
