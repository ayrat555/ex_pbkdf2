defmodule ExPBKDF2.Impl do
  @moduledoc false

  use Rustler, otp_app: :ex_pbkdf2, crate: :ex_pbkdf2

  def generate_salt(_format), do: :erlang.nif_error(:nif_not_loaded)

  def calculate_pbkdf2(_password, _salt, _alg, _iterations, _length, _format),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify(_hash, _password),
    do: :erlang.nif_error(:nif_not_loaded)
end
