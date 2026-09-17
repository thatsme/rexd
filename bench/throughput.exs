# Throughput of each stage over random data.
#
#     mix run bench/throughput.exs [megabytes]
#
# Every figure is input megabytes (MiB) per second of wall-clock time on one
# scheduler, measured with :timer.tc. Results are printed as a Markdown table.

defmodule Bench.Throughput do
  alias Rexd.{Blake2b, RabinKarp, Signature}

  @block_len 2048
  @chunk 65_536

  def run(mb) do
    size = mb * 1024 * 1024
    basis = :crypto.strong_rand_bytes(size)
    edited = scattered_edits(basis, 100)
    unrelated = :crypto.strong_rand_bytes(size)
    zeros = :binary.copy(<<0>>, size)

    sig = basis |> Rexd.signature(block_len: @block_len) |> Signature.build_index()
    zero_sig = zeros |> Rexd.signature(block_len: @block_len) |> Signature.build_index()
    edited_delta = Rexd.delta(sig, edited)

    rows = [
      {"RabinKarp rolling update", size, fn -> roll(basis) end},
      {"BLAKE2b-256, 2 KiB blocks", size,
       fn -> for <<b::binary-2048 <- basis>>, do: Blake2b.hash(b) end},
      {"`Rexd.signature/2`", size, fn -> Rexd.signature(basis, block_len: @block_len) end},
      {"`Rexd.Stream.signature/2`", size,
       fn -> basis |> chunks() |> Rexd.Stream.signature(block_len: @block_len) |> drain() end},
      {"`Rexd.delta/2`, unrelated data", size, fn -> Rexd.delta(sig, unrelated) end},
      {"`Rexd.delta/2`, identical data", size, fn -> Rexd.delta(sig, basis) end},
      {"`Rexd.delta/2`, 100 scattered edits", size, fn -> Rexd.delta(sig, edited) end},
      {"`Rexd.delta/2`, all-zero data", size, fn -> Rexd.delta(zero_sig, zeros) end},
      {"`Rexd.Stream.delta/2`, unrelated data", size,
       fn -> sig |> Rexd.Stream.delta(chunks(unrelated)) |> drain() end},
      {"`Rexd.Stream.delta/2`, 100 scattered edits", size,
       fn -> sig |> Rexd.Stream.delta(chunks(edited)) |> drain() end},
      {"`Rexd.patch/3`, 100 scattered edits", byte_size(edited),
       fn -> Rexd.patch(basis, edited_delta) end}
    ]

    IO.puts("| Operation | MiB/s |")
    IO.puts("|-----------|------:|")

    for {name, bytes, fun} <- rows do
      :erlang.garbage_collect()
      {micros, _} = :timer.tc(fun)
      IO.puts("| #{name} | #{Float.round(bytes / 1_048_576 / (micros / 1.0e6), 1)} |")
    end
  end

  defp roll(data) do
    {mult, adj} = RabinKarp.window(@block_len)

    roll(
      data,
      0,
      RabinKarp.hash(binary_part(data, 0, @block_len)),
      byte_size(data) - @block_len,
      mult,
      adj
    )
  end

  defp roll(_data, last, weak, last, _mult, _adj), do: weak

  defp roll(data, pos, weak, last, mult, adj) do
    weak =
      RabinKarp.rotate(weak, :binary.at(data, pos), :binary.at(data, pos + @block_len), mult, adj)

    roll(data, pos + 1, weak, last, mult, adj)
  end

  # 100 edits of 10 bytes replaced by 15 random bytes, evenly spread.
  defp scattered_edits(basis, count) do
    size = byte_size(basis)

    Enum.reduce(count..1//-1, basis, fn i, acc ->
      at = div(size * i, count + 1)
      <<a::binary-size(at), _::binary-size(10), b::binary>> = acc
      a <> :crypto.strong_rand_bytes(15) <> b
    end)
  end

  defp chunks(data), do: Stream.unfold(data, &split_chunk/1)

  defp split_chunk(<<>>), do: nil
  defp split_chunk(<<chunk::binary-size(@chunk), rest::binary>>), do: {chunk, rest}
  defp split_chunk(rest), do: {rest, <<>>}

  defp drain(stream), do: Enum.reduce(stream, 0, &(&2 + byte_size(&1)))
end

System.argv() |> List.first("20") |> String.to_integer() |> Bench.Throughput.run()
