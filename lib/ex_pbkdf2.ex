defmodule ExPBKDF2 do
  alias ExPBKDF2.Impl

  defdelegate generate_salt(), to: Impl

  def pbkdf2(password, opts \\ []) do
    salt = Keyword.get(opts, :salt, generate_salt())
    alg = Keyword.get(opts, :alg, "sha512")
    iterations = Keyword.get(opts, :iterations, 4096)
    length = Keyword.get(opts, :length, 64)
    format = Keyword.get(opts, :format, false)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length, format)
  end

  def verify(hash, password, formatted: true), do: Impl.verify(hash, password)

  def verify(hash, password, salt: salt, alg: alg, iterations: iterations, length: length) do
    formatted_hash = "$pbkdf2-#{alg}$i=#{iterations},l=#{length}$#{salt}$#{hash}"

    Impl.verify(formatted_hash, password)
  end
end
