defmodule ExPBKDF2 do
  alias ExPBKDF2.Impl

  defdelegate generate_salt(), to: Impl
  defdelegate verify(hash, password), to: Impl

  def pbkdf2(password, opts \\ []) do
    salt = Keyword.get(opts, :salt, generate_salt())
    alg = Keyword.get(opts, :alg, "sha512")
    iterations = Keyword.get(opts, :iterations, 4096)
    length = Keyword.get(opts, :length, 32)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length)
  end
end
