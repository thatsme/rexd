defmodule Rexd.Test.Oracle do
  @moduledoc false
  # Thin wrappers around the external reference tools. Test modules that use
  # them are tagged with the tool name; test_helper.exs excludes the tag when
  # the tool is not on PATH.

  @tools [:rdiff, :b2sum]

  def tools, do: @tools

  def available?(tool) when tool in @tools, do: System.find_executable(to_string(tool)) != nil

  def rdiff_signature(basis, block_len, strong_sum_len, dir) do
    basis_path = write(dir, "basis", basis)
    sig_path = Path.join(dir, "sig")
    rdiff!(["-b", "#{block_len}", "-S", "#{strong_sum_len}", "signature", basis_path, sig_path])
    File.read!(sig_path)
  end

  def rdiff_delta(signature, new, dir) do
    sig_path = write(dir, "delta-sig", signature)
    new_path = write(dir, "new", new)
    delta_path = Path.join(dir, "delta")
    rdiff!(["delta", sig_path, new_path, delta_path])
    File.read!(delta_path)
  end

  def rdiff_patch(basis, delta, dir) do
    {:ok, patched} = rdiff_patch_result(basis, delta, dir)
    patched
  end

  # {:ok, patched} or {:error, rdiff_output} when rdiff refuses the delta.
  def rdiff_patch_result(basis, delta, dir) do
    basis_path = write(dir, "patch-basis", basis)
    delta_path = write(dir, "patch-delta", delta)
    out_path = Path.join(dir, "patched")

    case System.cmd("rdiff", ["-f", "patch", basis_path, delta_path, out_path],
           stderr_to_stdout: true
         ) do
      {_, 0} -> {:ok, File.read!(out_path)}
      {out, _code} -> {:error, out}
    end
  end

  def b2sum256(data, dir) do
    path = write(dir, "b2-input", data)
    {out, 0} = System.cmd("b2sum", ["-l", "256", path])
    [hex | _] = String.split(out)
    Base.decode16!(hex, case: :lower)
  end

  defp rdiff!(args) do
    case System.cmd("rdiff", ["-f" | args], stderr_to_stdout: true) do
      {_, 0} -> :ok
      {out, code} -> raise "rdiff #{Enum.join(args, " ")} exited #{code}: #{out}"
    end
  end

  defp write(dir, name, data) do
    path = Path.join(dir, name)
    File.write!(path, data)
    path
  end
end
