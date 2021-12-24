# ExPBKDF2

Rust NIf for [Password-Based Key Derivation Function v2 (PBKDF2)](https://en.wikipedia.org/wiki/PBKDF2). It uses the [pbkdf2](https://github.com/RustCrypto/password-hashes/tree/master/pbkdf2) rust library.

## Installation

The package can be installed by adding `ex_pbkdf2` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_pbkdf2, "~> 0.1"}
  ]
end
```

The minimum supported rust version is 1.51

## Usage

EXPBKDF2 provides three functions:

- `generate_salt/1` - generates salt that can be used in `pbkdf2/2`
- `pbkdf2/2` - hashes the provided password
- `verify/3` - verifies the hash

### generate_salt/1

`generate_salt/1` accepts one parameter - format_flag. if it's true, the salt is encoded into b64 format, otherwise, a raw binary is returned.

```elixir
ExPBKDF2.generate_salt(true)
\\ "SqeHk0Kbypmuj0lPVQsIpA"

ExPBKDF2.generate_salt()
\\ <<86, 203, 205, 255, 49, 164, 123, 49, 106, 130, 250, 222, 107, 90, 58, 9>>
```

### pbkdf2/2

`pbkdf2` accepts two parameters - password and optional parameters map. The optional parameters include:

- `:salt` - if it's not set, it will be generated
- `:alg` - the hashing algorithm to be used. it can be `"sha512"` or `"sha256"`. Default value is `"sha512"`
- `:iterations` - the number of iterations. The default value is 4096
- `:length` - the length of the result. The default value is 64
- `:format` - boolean flag. if it's true, the result will be returned in b64 format, otherwise, it will be returned as raw binary. The default value is `false`.

```elixir
opts = %{salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32, format: true}
ExPBKDF2.pbkdf2("password", opts)
\\ "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
```

### verify/3

`verify/3` accepts three parameters:

- hash - hash generated with pbkdf2
- password - used password
- optional parameters map - it's almost the same as options for `pbkdf2`, the only exception is `format` flag is not needed.

```elixir
opts = %{salt: "c2FsdA", alg: "sha256", iterations: 4096, length: 32}
hash = "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o"
password = "password"

ExPBKDF2.verify(hash, password, opts)
\\ true
```

## Benchmarks

This NIF is 5 times faster than [pbkdf2_elixir](https://github.com/riverrun/pbkdf2_elixir) - 4.48 ms vs 22.89.ms. It also performs better in terms of used memory. Benchmarks can be found in the `benchmarks` directory


## Contributing

1. [Fork it!](https://github.com/ayrat555/ex_pbkdf2)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Author

Ayrat Badykov (@ayrat555)
