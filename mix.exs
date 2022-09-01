defmodule ExPbkdf2.MixProject do
  use Mix.Project

  @source_url "https://github.com/ayrat555/ex_pbkdf2"

  def project do
    [
      app: :ex_pbkdf2,
      version: "0.6.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package()
    ]
  end

  defp description do
    """
    Pbkdf2 for Elixir by a Rust-based NIF
    """
  end

  defp package do
    [
      name: :ex_pbkdf2,
      maintainers: ["Ayrat Badykov"],
      licenses: ["MIT"],
      links: %{
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md",
        "GitHub" => @source_url
      },
      files: [
        "mix.exs",
        "native/ex_pbkdf2/.cargo/config",
        "native/ex_pbkdf2/src",
        "native/ex_pbkdf2/Cargo.toml",
        "native/ex_pbkdf2/Cargo.lock",
        "lib",
        "LICENSE",
        "README.md",
        "CHANGELOG.md"
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
      {:rustler, "~> 0.25"},
      {:benchee, "~> 1.0", only: :test},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
