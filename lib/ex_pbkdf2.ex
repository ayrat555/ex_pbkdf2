defmodule ExPBKDF2 do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()

  alias ExPBKDF2.Impl

  @spec generate_salt() :: binary() | no_return()
  def generate_salt() do
    Impl.generate_salt()
  end

  @spec pbkdf2(binary(), map() | nil) :: binary() | no_return()
  def pbkdf2(password, opts \\ %{}) do
    salt = Map.get(opts, :salt, generate_salt())
    alg = Map.get(opts, :alg, "sha512")
    iterations = Map.get(opts, :iterations, 4096)
    length = Map.get(opts, :length, 64)

    Impl.calculate_pbkdf2(password, salt, alg, iterations, length)
  end

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
