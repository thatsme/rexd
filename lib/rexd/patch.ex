defmodule Rexd.Patch do
  @moduledoc """
  Applies a `Rexd.Delta` to a basis binary.

  The commands are checked before any output is built: every copy must lie
  inside the basis, and the total output size can be capped with
  `:max_size`. A delta is usually received from another party, and a few
  bytes of copy commands can describe an output many times larger than the
  delta itself, so callers that do not trust the sender should set a limit.

  On success the result is built in a single `IO.iodata_to_binary/1`: copy
  commands contribute sub-binaries of the basis and literal commands their
  own bytes.
  """

  alias Rexd.Delta

  @type error ::
          {:copy_out_of_range, non_neg_integer(), non_neg_integer()}
          | {:output_too_large, non_neg_integer(), non_neg_integer()}

  @doc "Applies `delta` to `basis`. See `Rexd.patch/3` for options and errors."
  @spec apply_delta(binary(), Delta.t(), keyword()) :: {:ok, binary()} | {:error, error()}
  def apply_delta(basis, %Delta{commands: commands}, opts \\ []) when is_binary(basis) do
    max_size =
      opts
      |> Keyword.validate!(max_size: :infinity)
      |> Keyword.fetch!(:max_size)
      |> valid_max_size!()

    with {:ok, size} <- output_size(commands, byte_size(basis), 0),
         :ok <- check_size(size, max_size) do
      {:ok, commands |> Enum.map(&command_bytes(&1, basis)) |> IO.iodata_to_binary()}
    end
  end

  defp valid_max_size!(:infinity), do: :infinity
  defp valid_max_size!(size) when is_integer(size) and size >= 0, do: size

  defp valid_max_size!(other),
    do:
      raise(
        ArgumentError,
        "max_size must be a non-negative integer or :infinity, got: #{inspect(other)}"
      )

  defp output_size([], _basis_size, total), do: {:ok, total}

  defp output_size([{:literal, data} | rest], basis_size, total) when is_binary(data),
    do: output_size(rest, basis_size, total + byte_size(data))

  defp output_size([{:copy, offset, len} | rest], basis_size, total)
       when is_integer(offset) and offset >= 0 and is_integer(len) and len >= 0 and
              offset + len <= basis_size,
       do: output_size(rest, basis_size, total + len)

  defp output_size([{:copy, offset, len} | _rest], _basis_size, _total)
       when is_integer(offset) and offset >= 0 and is_integer(len) and len >= 0,
       do: {:error, {:copy_out_of_range, offset, len}}

  defp check_size(_size, :infinity), do: :ok
  defp check_size(size, max_size) when size <= max_size, do: :ok
  defp check_size(size, max_size), do: {:error, {:output_too_large, size, max_size}}

  defp command_bytes({:literal, data}, _basis), do: data
  defp command_bytes({:copy, offset, len}, basis), do: binary_part(basis, offset, len)
end
