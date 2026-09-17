# Peak memory of signature, delta and patch over large inputs.
#
#     mix run bench/memory.exs [megabytes]
#
# Two scenarios over a basis of the given size (default 100 MiB) and a copy of
# it with scattered edits and insertions:
#
#   * whole-binary: basis and new data held in memory, Rexd.delta/2 and
#     Rexd.patch/3;
#   * streaming: both files on disk, Rexd.Stream.signature/2, delta/2 and
#     patch/3 between files, with the basis read through :file.pread/3.
#
# A sampler process records :erlang.memory(:processes) and
# :erlang.memory(:binary) every millisecond. Each figure is the peak during the
# operation minus the level just before it, the largest over three runs.
# Process memory includes short-lived garbage not yet collected; binary memory
# shows whether input data is copied. Total VM memory is not used: it also
# moves with deallocations left over from earlier work and with other
# processes, which makes single readings unreliable.

defmodule Bench.Memory do
  alias Rexd.Signature

  @block_len 2048
  @chunk 65_536

  def run(mb) do
    dir = Path.join(System.tmp_dir!(), "rexd-bench-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    try do
      IO.puts("| Scenario (#{mb} MiB) | Operation | Process heap peak | Binary peak |")
      IO.puts("|----------|-----------|------------------:|------------:|")
      whole_binary(mb)
      streaming(mb, dir)
    after
      File.rm_rf!(dir)
    end
  end

  defp whole_binary(mb) do
    basis = :crypto.strong_rand_bytes(mb * 1_048_576)
    # A binary built by repeated appends keeps spare capacity; the VM may copy
    # it once when it is first matched or sliced. :binary.copy/1 makes it
    # compact so that one-time copy is not attributed to Rexd.delta/2.
    new = :binary.copy(edit(basis))
    unrelated = :crypto.strong_rand_bytes(mb * 1_048_576)

    sig =
      measure("whole-binary", "`Rexd.signature/2`", fn ->
        Rexd.signature(basis, block_len: @block_len)
      end)

    sig = Signature.build_index(sig)
    delta = measure("whole-binary", "`Rexd.delta/2`, edited", fn -> Rexd.delta(sig, new) end)
    measure("whole-binary", "`Rexd.delta/2`, unrelated", fn -> Rexd.delta(sig, unrelated) end)

    {:ok, ^new} =
      measure("whole-binary", "`Rexd.patch/3` (output #{mb} MiB)", fn ->
        Rexd.patch(basis, delta)
      end)

    :ok
  end

  defp streaming(mb, dir) do
    basis_path = Path.join(dir, "basis")
    new_path = Path.join(dir, "new")
    sig_path = Path.join(dir, "sig")
    delta_path = Path.join(dir, "delta")
    out_path = Path.join(dir, "out")

    write_random(basis_path, mb)
    write_edited(basis_path, new_path)

    measure("streaming", "`Rexd.Stream.signature/2`", fn ->
      basis_path
      |> File.stream!(@chunk)
      |> Rexd.Stream.signature(block_len: @block_len)
      |> Stream.into(File.stream!(sig_path))
      |> Stream.run()
    end)

    {:ok, sig} = sig_path |> File.read!() |> Signature.decode()
    sig = Signature.build_index(sig)

    measure("streaming", "`Rexd.Stream.delta/2`", fn ->
      sig
      |> Rexd.Stream.delta(File.stream!(new_path, @chunk))
      |> Stream.into(File.stream!(delta_path))
      |> Stream.run()
    end)

    {:ok, io} = :file.open(basis_path, [:read, :binary, :raw])

    read = fn offset, len ->
      case :file.pread(io, offset, len) do
        {:ok, data} -> data
        :eof -> <<>>
      end
    end

    measure("streaming", "`Rexd.Stream.patch/3`", fn ->
      read
      |> Rexd.Stream.patch(File.stream!(delta_path, @chunk))
      |> Stream.into(File.stream!(out_path))
      |> Stream.run()
    end)

    :file.close(io)
    true = digest(out_path) == digest(new_path)

    IO.puts(
      "\nstreamed delta: #{div(File.stat!(delta_path).size, 1024)} KiB; patched output verified"
    )
  end

  defp measure(scenario, name, fun) do
    {result, peaks} =
      Enum.reduce(1..3, {nil, %{processes: 0, binary: 0}}, fn _run, {_result, worst} ->
        {result, peaks} = peaks(fun)
        {result, Map.merge(worst, peaks, fn _kind, a, b -> max(a, b) end)}
      end)

    IO.puts("| #{scenario} | #{name} | #{format(peaks.processes)} | #{format(peaks.binary)} |")
    result
  end

  defp peaks(fun) do
    :erlang.garbage_collect()
    baseline = snapshot()
    sampler = spawn_link(fn -> sample(baseline) end)
    result = fun.()
    send(sampler, {:stop, self()})
    peak = receive do: ({:peak, peak} -> peak)
    {result, Map.new(peak, fn {kind, bytes} -> {kind, bytes - baseline[kind]} end)}
  end

  defp snapshot, do: %{processes: :erlang.memory(:processes), binary: :erlang.memory(:binary)}

  defp sample(peak) do
    peak = Map.merge(peak, snapshot(), fn _kind, a, b -> max(a, b) end)

    receive do
      {:stop, from} -> send(from, {:peak, peak})
    after
      1 -> sample(peak)
    end
  end

  defp format(bytes) when bytes < 1_048_576, do: "#{div(max(bytes, 0), 1024)} KiB"
  defp format(bytes), do: "#{Float.round(bytes / 1_048_576, 1)} MiB"

  defp edit(basis) do
    size = byte_size(basis)

    Enum.reduce(100..1//-1, basis, fn i, acc ->
      at = div(size * i, 101)
      <<a::binary-size(at), _::binary-size(10), b::binary>> = acc
      a <> :crypto.strong_rand_bytes(15) <> b
    end)
  end

  defp write_random(path, mb) do
    File.open!(path, [:write, :binary], fn file ->
      for _ <- 1..mb, do: IO.binwrite(file, :crypto.strong_rand_bytes(1_048_576))
    end)
  end

  # Copies the basis in 1 MiB pieces, replacing 10 bytes of each with 15 random bytes.
  defp write_edited(basis_path, new_path) do
    File.open!(new_path, [:write, :binary], fn file ->
      for <<a::binary-size(500_000), _::binary-size(10), b::binary>> <-
            File.stream!(basis_path, 1_048_576) do
        IO.binwrite(file, [a, :crypto.strong_rand_bytes(15), b])
      end
    end)
  end

  defp digest(path) do
    path
    |> File.stream!(@chunk)
    |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
    |> :crypto.hash_final()
  end
end

System.argv() |> List.first("100") |> String.to_integer() |> Bench.Memory.run()
