defmodule Rexd.Delta.Search do
  @moduledoc false
  # The rsync delta search over a binary.
  #
  # Phase 1 (scan): a full block_len window slides over `new` one byte at a
  # time. Each window is classified against the signature:
  #
  #   * miss            - weak checksum not in the index
  #   * :false_hit      - weak checksum found, strong hash matches no block
  #   * {:match, block} - a block with equal weak and strong checksums
  #
  # A match emits a copy and restarts the window right after it; anything
  # else rolls the window forward by one byte. Misses are by far the most
  # common case and are handled directly in scan/4.
  #
  # Phase 2 (tail): once no full window fits, the window shrinks from the
  # front. Only the last basis block can be shorter than block_len, so it is
  # the only candidate.
  #
  # `Context` is fixed for the whole search. `Output` changes only when a
  # window hits the index, so the per-byte path allocates nothing.
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
    # last_full is the final position where a full window fits (negative when
    # none does); mult and adj are the RabinKarp constants for block_len.
    @enforce_keys [
      :new,
      :size,
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
    # commands are accumulated in reverse; literal_start is the offset in `new`
    # of the first byte not yet covered by a command; next_block is the block
    # that would extend the most recent copy.
    defstruct commands: [], literal_start: 0, next_block: nil, weak_hits: 0, false_weak_hits: 0
  end

  @spec run(Signature.t(), binary()) :: {[Delta.command()], Delta.stats()}
  def run(%Signature{} = sig, new) when is_binary(new) do
    ctx = context(Signature.build_index(sig), new)
    out = search(ctx)

    {Enum.reverse(out.commands),
     %{weak_hits: out.weak_hits, false_weak_hits: out.false_weak_hits}}
  end

  defp context(%Signature{} = sig, new) do
    size = byte_size(new)
    {mult, adj} = RabinKarp.window(sig.block_len)

    %Context{
      new: new,
      size: size,
      block_len: sig.block_len,
      strong_sum_len: sig.strong_sum_len,
      index: sig.index,
      blocks: List.to_tuple(sig.blocks),
      block_count: length(sig.blocks),
      last_full: size - sig.block_len,
      mult: mult,
      adj: adj
    }
  end

  defp search(%Context{size: 0} = ctx), do: finish(%Output{}, ctx)
  defp search(%Context{block_count: 0} = ctx), do: finish(%Output{}, ctx)

  defp search(%Context{last_full: last_full} = ctx) when last_full >= 0,
    do: scan(0, weak_at(ctx, 0, ctx.block_len), ctx, %Output{})

  defp search(ctx), do: tail(0, weak_at(ctx, 0, ctx.size), ctx, %Output{})

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
        after_match(pos + ctx.block_len, ctx, out)

      :false_hit ->
        advance(pos, weak, ctx, record(out, :false_hit))
    end
  end

  # Per-byte hot path: one destructuring match instead of five ctx.field lookups.
  defp advance(pos, weak, %Context{last_full: last_full} = ctx, out) when pos < last_full do
    %Context{new: new, block_len: block_len, mult: mult, adj: adj} = ctx

    weak =
      RabinKarp.rotate(weak, :binary.at(new, pos), :binary.at(new, pos + block_len), mult, adj)

    scan(pos + 1, weak, ctx, out)
  end

  defp advance(pos, weak, ctx, out), do: tail(pos + 1, drop_first(weak, ctx, pos), ctx, out)

  defp after_match(pos, %Context{last_full: last_full} = ctx, out) when pos <= last_full,
    do: scan(pos, weak_at(ctx, pos, ctx.block_len), ctx, out)

  defp after_match(pos, ctx, out), do: tail(pos, weak_at(ctx, pos, ctx.size - pos), ctx, out)

  # -- phase 2: shrinking window at the end of `new` ------------------------------

  defp tail(pos, _weak, %Context{size: pos} = ctx, out), do: finish(out, ctx)

  defp tail(pos, weak, ctx, out) do
    len = ctx.size - pos

    case classify_tail(pos, len, weak, ctx) do
      {:match, block} = result ->
        out |> record(result) |> emit_copy(ctx, pos, block, len) |> finish(ctx)

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
      _ -> candidate_match(List.keyfind(candidates, strong, 1))
    end
  end

  defp next_block_checksums(_ctx, nil), do: nil
  defp next_block_checksums(%Context{block_count: count}, next) when next >= count, do: nil
  defp next_block_checksums(%Context{blocks: blocks}, next), do: elem(blocks, next)

  defp candidate_match({block, _strong}), do: {:match, block}
  defp candidate_match(nil), do: :false_hit

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

  defp finish(out, ctx), do: flush_literal(out, ctx, ctx.size)

  defp flush_literal(%Output{literal_start: pos} = out, _ctx, pos), do: out

  defp flush_literal(%Output{literal_start: start} = out, ctx, pos) do
    literal = {:literal, binary_part(ctx.new, start, pos - start)}
    %{out | commands: [literal | out.commands], literal_start: pos}
  end

  # -- checksums ---------------------------------------------------------------

  defp weak_at(ctx, pos, len), do: RabinKarp.hash(binary_part(ctx.new, pos, len))

  defp strong_at(ctx, pos, len),
    do: Signature.strong(binary_part(ctx.new, pos, len), ctx.strong_sum_len)

  # Removes new[pos] from the front of the window new[pos, size).
  defp drop_first(weak, ctx, pos) do
    {mult, adj} = RabinKarp.window(ctx.size - pos - 1)
    RabinKarp.rollout(weak, :binary.at(ctx.new, pos), mult, adj)
  end
end
