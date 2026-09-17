defmodule Rexd.StreamError do
  @moduledoc """
  Raised while a `Rexd.Stream` enumerable is consumed and its input turns out
  to be invalid.

  `reason` uses the same terms as the error tuples of the non-streaming API,
  for example `{:bad_magic, magic}`, `:truncated`, `{:copy_out_of_range,
  offset, length}` or `{:output_too_large, size, max_size}`.
  """

  defexception [:reason]

  @type t :: %__MODULE__{reason: term()}

  @impl true
  def message(%__MODULE__{reason: reason}), do: "invalid delta stream: #{inspect(reason)}"
end
