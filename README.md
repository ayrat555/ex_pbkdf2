# ExPBKDF2

Rust NIf for [Password-Based Key Derivation Function v2 (PBKDF2)](https://en.wikipedia.org/wiki/PBKDF2). It uses the [pbkdf2](https://github.com/RustCrypto/password-hashes/tree/master/pbkdf2) rust library.

## Installation

The package can be installed by adding `ex_pbkdf2` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_pbkdf2, "~> 0.8.5"}
  ]
end
```

## Usage

EXPBKDF2 provides three functions:

- `generate_salt/1` - generates salt that can be used in `pbkdf2/2`
- `pbkdf2/2` - hashes the provided password
- `verify/3` - verifies the hash

The docs can be found at [https://hexdocs.pm/ex_pbkdf2](https://hexdocs.pm/ex_pbkdf2).

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
