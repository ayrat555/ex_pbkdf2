defmodule ExPBKDF2 do
  use Rustler, otp_app: :ex_pbkdf2, crate: :ex_pbkdf2

  def generate_salt(), do: :erlang.nif_error(:nif_not_loaded)

  def calculate_pbkdf2(password, salt, alg, iterations), do: :erlang.nif_error(:nif_not_loaded)

  def verify(hash, password, salt, alg, interations), do: :erlang.nif_error(:nif_not_loaded)
end
