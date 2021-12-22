defmodule ExPbkdf2Test do
  use ExUnit.Case

  describe "pbkdf2/2" do
    test "calculates pbkdf2" do
      expected_formatted_result =
        "$pbkdf2-sha256$i=4096,l=32$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"

      opts = [salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32]

      assert expected_formatted_result == ExPBKDF2.pbkdf2("password", opts)
    end

    test "generates salt if it's not provided" do
      assert ExPBKDF2.pbkdf2("password")
    end
  end

  describe "verify/2" do
    test "verifies hash" do
      hash = "$pbkdf2-sha256$i=4096,l=32$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
      password = "password"

      assert ExPBKDF2.verify(hash, password)
    end
  end
end
