defmodule ExPBKDF2 do
  @moduledoc """
  Rust NIf for [Password-Based Key Derivation Function v2 (PBKDF2)](https://en.wikipedia.org/wiki/PBKDF2). It uses the [pbkdf2](https://github.com/RustCrypto/password-hashes/tree/master/pbkdf2) rust library.
  """

  alias ExPBKDF2.Impl

  @doc """
  Generate a random salt

  Examples

      iex> salt = ExPBKDF2.generate_salt()
      iex> byte_size(salt)
      16
  """
  @spec generate_salt() :: binary() | no_return()
  def generate_salt do
    Impl.generate_salt()
  end

  @doc """
  Hash the provided password

  It accepts a map with optional parameters:

  - `:salt` - if it's not set, it will be generated
  - `:alg` - the hashing algorithm to be used. it can be `"sha512"` or `"sha256"`. Default value is `"sha512"`
  - `:iterations` - the number of iterations. The default value is 4096
  - `:length` - the length of the result. The default value is 64

  Examples

      iex> opts = %{salt: "salt", alg: "sha256", iterations: 4096, length: 32}
      iex> ExPBKDF2.pbkdf2("password", opts)
      <<197, 228, 120, 213, 146, 136, 200, 65, 170, 83, 13, 182, 132, 92, 76, 141, 150, 40, 147, 160, 1, 206, 78, 17, 164, 150, 56, 115, 170, 152, 19, 74>>
  """
  @spec pbkdf2(binary(), map() | nil) :: binary() | no_return()
  def pbkdf2(password, opts \\ %{}) do
    salt = Map.get(opts, :salt, generate_salt())
    alg = Map.get(opts, :alg, "sha512")
    iterations = Map.get(opts, :iterations, 4096)
    length = Map.get(opts, :length, 64)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length)
  end

  @doc """
  Verify the provided hash

  It accepts three parameters:

  - hash - hash generated with pbkdf2
  - password - used password
  - optional parameters map - it's the same as options for `pbkdf2/2`. If this parameter is not passed, it's assumed that hash is already in the PHC string format

  Examples

      iex> hash = <<197, 228, 120, 213, 146, 136, 200, 65, 170, 83, 13, 182, 132, 92, 76, 141, 150, 40, 147, 160, 1, 206, 78, 17, 164, 150, 56, 115, 170, 152, 19, 74>>
      iex> opts = %{salt: "salt", alg: "sha256", iterations: 4096, length: 32}
      iex> ExPBKDF2.verify(hash, "password", opts)
      true
  """
  @spec verify(binary(), binary(), map() | nil) :: boolean() | no_return()
  def verify(hash, password, params \\ nil)

  def verify(hash, password, %{salt: raw_salt, alg: alg, iterations: iterations, length: length}) do
    salt = Base.encode64(raw_salt, padding: false)
    hash = Base.encode64(hash, padding: false)
    formatted_hash = "$pbkdf2-#{alg}$i=#{iterations},l=#{length}$#{salt}$#{hash}"

    verify(formatted_hash, password)
  end

  def verify(formatted_hash, password, _), do: Impl.verify(formatted_hash, password)
end
