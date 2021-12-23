defmodule ExPbkdf2Test do
  use ExUnit.Case

  describe "pbkdf2/2" do
    test "calculates pbkdf2 and format to b64" do
      expected_formatted_result = "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"

      opts = %{salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32, format: true}

      assert expected_formatted_result == ExPBKDF2.pbkdf2("password", opts)
    end

    test "calculates pbkdf2 and returns raw binary" do
      expected_formatted_result = "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"

      opts = %{salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32, format: false}

      assert expected_formatted_result ==
               "password" |> ExPBKDF2.pbkdf2(opts) |> Base.encode64(padding: false)
    end

    test "generates salt if it's not provided" do
      assert ExPBKDF2.pbkdf2("password")
    end
  end

  describe "verify/3" do
    test "verifies hash" do
      hash = "$pbkdf2-sha256$i=4096,l=32$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
      password = "password"

      assert ExPBKDF2.verify(hash, password, %{formatted: true})
    end

    test "fails to verify" do
      hash = "$pbkdf2-sha256$i=4096,l=32$c2FsdA$xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
      password = "password1"

      refute ExPBKDF2.verify(hash, password, %{formatted: true})
    end

    test "formats and verifies" do
      opts = %{salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32}
      hash = "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
      password = "password"

      assert ExPBKDF2.verify(hash, password, opts)
    end
  end

  describe "generate_salt/1" do
    test "returns raw salt if format if false" do
      assert binary = ExPBKDF2.generate_salt(false)

      assert :error = Base.decode64(binary)
    end

    test "returns b64 encoded salt if format is true" do
      assert binary = ExPBKDF2.generate_salt(true)

      assert {:ok, _val} = Base.decode64(binary, padding: false)
    end
  end

  @tag :perf
  @tag timeout: 300_000
  test "sequencial performance test" do
    Benchee.run(
      %{
        "pbkdf2_seq" => fn ->
          salt = ExPBKDF2.generate_salt(true)

          opts = %{salt: salt, alg: "sha512", iterations: 4096, length: 64, format: true}

          ExPBKDF2.pbkdf2("password", opts)
        end
      },
      time: 100,
      memory_time: 100
    )
  end

  @tag :perf
  @tag timeout: 300_000
  test "parallel performance test" do
    Benchee.run(
      %{
        "pbkdf2_par" => fn ->
          salt = ExPBKDF2.generate_salt(true)

          opts = %{salt: salt, alg: "sha512", iterations: 4096, length: 64, format: true}

          ExPBKDF2.pbkdf2("password", opts)
        end
      },
      time: 100,
      memory_time: 100,
      parallel: 4
    )
  end

  test "base pbkdf2_sha512 tests" do
    [
      {
        "passDATAb00AB7YxDTT",
        Base.encode64("saltKEYbcTcXHCBxtjD", padding: false),
        100_000,
        "rM3Nh5iuXNhYBHOQFe8qEeMlkbe30W92gZswsNSdgOGr6myYIrgKH9/kIeJvVgPsqKR6ZMmgBPta+CKfdi/0Hw"
      },
      {
        "passDATAb00AB7YxDTTl",
        Base.encode64("saltKEYbcTcXHCBxtjD2", padding: false),
        100_000,
        "WUJWsL1NbJ8hqH97pXcqeRoQ5hEGlPRDZc2UZw5X8a7NeX7x0QAZOHGQRMfwGAJml4Reua2X2X3jarh4aqtQlg"
      }
    ]
    |> check_vectors("sha512")
  end

  test "Python passlib pbkdf2_sha512 tests" do
    [
      {
        "password",
        Base.encode64(
          <<36, 196, 248, 159, 51, 166, 84, 170, 213, 250, 159, 211, 154, 83, 10, 193>>,
          padding: false
        ),
        19_000,
        "jKbZHoPwUWBT08pjb/CnUZmFcB9JW4dsOzVkfi9X6Pdn5NXWeY+mhL1Bm4V9rjYL5ZfA32uh7Gl2gt5YQa/JCA"
      },
      {
        "p@$$w0rd",
        Base.encode64(<<252, 159, 83, 202, 89, 107, 141, 17, 66, 200, 121, 239, 29, 163, 20, 34>>,
          padding: false
        ),
        19_000,
        "AJ3Dr926ltK1sOZMZAAoT7EoR7R/Hp+G6Bt+4DFENiYayhVM/ZBPuqjFNhcE9NjTmceTmLnSqzfEQ8mafy49sw"
      },
      {
        "oh this is hard 2 guess",
        Base.encode64(<<1, 96, 140, 17, 162, 84, 42, 165, 84, 42, 165, 244, 62, 71, 136, 177>>,
          padding: false
        ),
        19_000,
        "F0xkzJUOKaH8pwAfEwLeZK2/li6CF3iEcpfoJ1XoExQUTStXCNVxE1sd1k0aeQlSFK6JnxJOjM18kZIdzNYkcQ"
      },
      {
        "even more difficult",
        Base.encode64(<<215, 186, 87, 42, 133, 112, 14, 1, 160, 52, 38, 100, 44, 229, 92, 203>>,
          padding: false
        ),
        19_000,
        "TEv9woSaVTsYHLxXnFbWO1oKrUGfUAljkLnqj8W/80BGaFbhccG8B9fZc05RoUo7JQvfcwsNee19g8GD5UxwHA"
      }
    ]
    |> check_vectors("sha512")
  end

  test "Consistency tests for sha512" do
    [
      {
        "funferal",
        Base.encode64(<<192, 39, 248, 127, 11, 37, 71, 252, 74, 75, 244, 70, 129, 27, 51, 71>>,
          padding: false
        ),
        60_000,
        "QJHazw8zTaY0HvGQF1Slb07Ug9DFFLjoq63aORwhA+o/OM+e9UpxldolWyCNLv3duHuxpEWoZtGHfm3VTFCqpg"
      },
      {
        "he's N0t the Me551ah!",
        Base.encode64(<<60, 130, 11, 97, 11, 23, 236, 250, 227, 233, 56, 1, 86, 131, 41, 163>>,
          padding: false
        ),
        60_000,
        "tsPUY4uMzTbJuv81xxZzsUGvT1LGjk9EfJuAYoZH9KaCSGH90J8BuQwY4Jb0JZbwOI00BSR4hDBVmn3Z8V+Ywg"
      },
      {
        "ἓν οἶδα ὅτι οὐδὲν οἶδα",
        Base.encode64(<<29, 10, 228, 45, 215, 110, 213, 118, 168, 14, 197, 198, 67, 72, 34, 221>>,
          padding: false
        ),
        60_000,
        "UVkPApVkIkQN0FTQwaKffYoZ5Mbh0712p1GWs9H1Z+fBNQScUWCj/GAUtZDYMkIN3kIi9ORvut+SQ7aBipcpDQ"
      }
    ]
    |> check_vectors("sha512")
  end

  test "Consistency tests for sha256" do
    [
      {
        "funferal",
        Base.encode64(<<192, 39, 248, 127, 11, 37, 71, 252, 74, 75, 244, 70, 129, 27, 51, 71>>,
          padding: false
        ),
        60_000,
        "p1XmqbB8u/EfvftMDoLyL4ZcVKT6Nz+Y4E/8xuoRePA"
      },
      {
        "he's N0t the Me551ah!",
        Base.encode64(<<60, 130, 11, 97, 11, 23, 236, 250, 227, 233, 56, 1, 86, 131, 41, 163>>,
          padding: false
        ),
        80_000,
        "ErhanHiaHKh63nxft7nMS7rRpglbrZdQ6tEAhyrd+tQ"
      },
      {
        "ἓν οἶδα ὅτι οὐδὲν οἶδα",
        Base.encode64(<<29, 10, 228, 45, 215, 110, 213, 118, 168, 14, 197, 198, 67, 72, 34, 221>>,
          padding: false
        ),
        100_000,
        "egGo+5eQIb9Ulp27Xyc7WkesMu/u4mksXknuExBUCnc"
      }
    ]
    |> check_vectors("sha256", 32)
  end

  defp check_vectors(vectors, alg, length \\ 64) do
    for {password, salt, iterations, hash} <- vectors do
      opts = %{salt: salt, alg: alg, iterations: iterations, length: length, format: true}

      calc_hash = ExPBKDF2.pbkdf2(password, opts)

      assert hash == calc_hash
      assert ExPBKDF2.verify(calc_hash, password, opts)
    end
  end
end
