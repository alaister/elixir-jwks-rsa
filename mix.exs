defmodule JwksRsa.MixProject do
  use Mix.Project

  def project do
    [
      app: :jwks_rsa,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {JwksRsa.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:cachex, "~> 3.0"},
      {:httpoison, "~> 1.2"},
      {:poison, "~> 3.1"},
      {:joken, "~> 1.5"}
    ]
  end
end
