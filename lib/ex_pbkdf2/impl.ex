defmodule ExPBKDF2.Impl do
  @moduledoc false

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :ex_pbkdf2,
    crate: :ex_pbkdf2,
    base_url: "https://github.com/ayrat555/ex_pbkdf2/releases/download/v#{version}",
    force_build: System.get_env("RUSTLER_BUILD") in ["1", "true"],
    version: version

  def generate_salt, do: :erlang.nif_error(:nif_not_loaded)

  def calculate_pbkdf2(_password, _salt, _alg, _iterations, _length),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify(_hash, _password),
    do: :erlang.nif_error(:nif_not_loaded)
end
