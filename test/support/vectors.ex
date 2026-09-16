defmodule Rexd.Test.Vectors do
  @moduledoc false
  # Loads test/fixtures/vectors.term (see scripts/gen_vectors.exs), hex-decoded.

  @path Path.expand("../fixtures/vectors.term", __DIR__)
  @external_resource @path

  def signatures do
    for v <- load().signatures do
      %{
        v
        | basis: unhex(v.basis),
          new: unhex(v.new),
          rdiff_signature: unhex(v.rdiff_signature),
          rdiff_delta: unhex(v.rdiff_delta)
      }
    end
  end

  def blake2b do
    for v <- load().blake2b, do: {unhex(v.data), unhex(v.blake2b_256)}
  end

  defp load do
    {vectors, _} = Code.eval_file(@path)
    vectors
  end

  defp unhex(hex), do: Base.decode16!(hex, case: :lower)
end
