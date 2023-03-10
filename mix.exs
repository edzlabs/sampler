defmodule PDSZ.MixProject do
  use Mix.Project

  def project do
    [
      app: :pdsz,
      version: "0.1.0",
      elixir: "~> 1.15-dev",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "PDSZ",
        extras: ["README.md", "pdszlivebook.livemd"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:poison, "~> 5.0"},
      {:json, "~> 1.4"},
      {:uuid, "~> 1.1"},
      {:ex_doc, ">= 0.0.0", runtime: false, only: [:docs, :dev]},
      {:curvy, "~> 0.3.0"},
      {:ex_crypto, "~> 0.10.0"}

      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
