defmodule ExPBKDF2 do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()

  alias ExPBKDF2.Impl

  @spec generate_salt(boolean() | nil) :: binary() | String.t() | no_return()
  def generate_salt(format \\ false) do
    Impl.generate_salt(format)
  end

  @spec pbkdf2(map(), map() | nil) :: binary() | String.t() | no_return()
  def pbkdf2(password, opts \\ %{}) do
    salt = Map.get(opts, :salt, generate_salt())
    alg = Map.get(opts, :alg, "sha512")
    iterations = Map.get(opts, :iterations, 4096)
    length = Map.get(opts, :length, 64)
    format = Map.get(opts, :format, false)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length, format)
  end

  @spec verify(String.t(), String.t(), map() | nil) :: boolean() | no_return()
  def verify(hash, password, %{formatted: true}), do: Impl.verify(hash, password)

  def verify(hash, password, %{salt: raw_salt, alg: alg, iterations: iterations, length: length}) do
    salt = Base.encode64(raw_salt, padding: false)
    formatted_hash = "$pbkdf2-#{alg}$i=#{iterations},l=#{length}$#{salt}$#{hash}"

    Impl.verify(formatted_hash, password)
  end
end
