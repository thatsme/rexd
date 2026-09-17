# mix run bench/delta.exs [megabytes]
mb = String.to_integer(List.first(System.argv(), "20"))
size = mb * 1024 * 1024
block_len = 2048

basis = :crypto.strong_rand_bytes(size)

edited =
  Enum.reduce(1..100, basis, fn i, acc ->
    at = div(size * i, 101)
    <<a::binary-size(at), _::binary-size(10), b::binary>> = acc
    a <> :crypto.strong_rand_bytes(15) <> b
  end)

scenarios = [
  {"unrelated (all literal)", basis, :crypto.strong_rand_bytes(size)},
  {"identical (all copy)", basis, basis},
  {"100 scattered edits", basis, edited},
  {"all-zero identical", :binary.copy(<<0>>, size), :binary.copy(<<0>>, size)}
]

mbps = fn us, bytes -> Float.round(bytes / 1_048_576 / (us / 1.0e6), 1) end

IO.puts("#{mb} MB, block_len #{block_len}, strong_sum_len 32")

for {name, b, new} <- scenarios do
  :erlang.garbage_collect()
  {sig_us, sig} = :timer.tc(fn -> Rexd.signature(b, block_len: block_len) end)
  {idx_us, sig} = :timer.tc(fn -> Rexd.Signature.build_index(sig) end)
  :erlang.garbage_collect()
  {us, {delta, stats}} = :timer.tc(fn -> Rexd.Delta.compute_with_stats(sig, new) end)
  {:ok, ^new} = Rexd.patch(b, delta)

  IO.puts(
    String.pad_trailing(name, 26) <>
      "signature #{mbps.(sig_us, byte_size(b))} MB/s | index #{div(idx_us, 1000)} ms | " <>
      "delta #{mbps.(us, byte_size(new))} MB/s | commands #{length(delta.commands)} | " <>
      "weak hits #{stats.weak_hits}, false #{stats.false_weak_hits}"
  )
end
