defmodule Rexd.MixProject do
  use Mix.Project

  @version "0.1.0-dev"
  @source_url "https://github.com/thatsme/rexd"

  def project do
    [
      app: :rexd,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "Rexd",
      source_url: @source_url,
      dialyzer: [plt_add_apps: [:mix]]
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:stream_data, "~> 1.1", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    "The rsync algorithm as a pure-Elixir library: signature, delta and patch " <>
      "over binaries and streams, wire-compatible with librsync 2.x (rdiff)."
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["thatsme"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE CHANGELOG.md NOTES.md BENCH.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "NOTES.md", "BENCH.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      source_url: @source_url,
      groups_for_modules: [
        Core: [Rexd, Rexd.Signature, Rexd.Delta, Rexd.Delta.Stats, Rexd.Patch],
        Streaming: [Rexd.Stream, Rexd.StreamError],
        "In-place patching": [Rexd.InPlace],
        Checksums: [Rexd.WeakChecksum, Rexd.RabinKarp, Rexd.Rollsum, Rexd.Blake2b, Rexd.MD4]
      ]
    ]
  end
end
