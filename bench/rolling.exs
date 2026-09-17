defmodule Bench.Rolling do
  alias Rexd.RabinKarp

  def run(data, n) do
    {m, a} = RabinKarp.window(n)
    last = byte_size(data) - n
    loop(data, 0, RabinKarp.hash(binary_part(data, 0, n)), last, n, m, a)
  end

  defp loop(_data, pos, h, pos, _n, _m, _a), do: h

  defp loop(data, pos, h, last, n, m, a) do
    h = RabinKarp.rotate(h, :binary.at(data, pos), :binary.at(data, pos + n), m, a)
    loop(data, pos + 1, h, last, n, m, a)
  end
end

mb = 10
data = :crypto.strong_rand_bytes(mb * 1024 * 1024)
n = 2048
{us, h} = :timer.tc(fn -> Bench.Rolling.run(data, n) end)
^h = Rexd.RabinKarp.hash(binary_part(data, byte_size(data) - n, n))

IO.puts(
  "RabinKarp.rotate/5 over #{mb} MB, window #{n}: #{Float.round(mb / (us / 1.0e6), 1)} MB/s"
)
