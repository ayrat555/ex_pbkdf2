defmodule ExPBKDF2 do
  alias ExPBKDF2.Impl

  def generate_salt(format \\ false) do
    Impl.generate_salt(format)
  end

  def pbkdf2(password, opts \\ %{}) do
    salt = Map.get(opts, :salt, generate_salt(true))
    alg = Map.get(opts, :alg, "sha512")
    iterations = Map.get(opts, :iterations, 4096)
    length = Map.get(opts, :length, 64)
    format = Map.get(opts, :format, false)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length, format)
  end

  def verify(hash, password, %{formatted: true}), do: Impl.verify(hash, password)

  def verify(hash, password, %{salt: salt, alg: alg, iterations: iterations, length: length}) do
    formatted_hash = "$pbkdf2-#{alg}$i=#{iterations},l=#{length}$#{salt}$#{hash}"

    Impl.verify(formatted_hash, password)
  end
end
