<div align="center">
    <h1>Algorsand</h1>
    <a href="https://app.circleci.com/pipelines/github/qkniep/algorand-rs"><img src="https://img.shields.io/circleci/build/github/qkniep/algorand-rs/main?token=86739a8e33bf4ab2812b9771d04a7585fa90f80c&style=for-the-badge&logo=circleci" alt="Build Status"></a>
    <a href="https://codecov.io/gh/qkniep/algorand-rs"><img src="https://img.shields.io/codecov/c/github/qkniep/algorand-rs?label=test%20coverage&logo=codecov&style=for-the-badge" alt="Test Coverage"></a>
    <a href="https://crates.io/crates/algorsand"><img src="https://img.shields.io/crates/v/algorsand?logo=rust&style=for-the-badge" alt="crates.io"></a>
</div>
<br>

Algorsand is a Rust implementation of the Algorand blockchain,
which aims to be more performant than the original Algorand implementation in Go.
Providing not only the client/node but also tools for generating keypairs, signatures, and so on.
For now it is basically a Rust clone of [go-algorand](https://github.com/algorand/go-algorand/).

## Getting Started

```shell
cargo build
cargo tests
```

## Roadmap
- [ ] finish porting go-algorand
- [ ] setup Concourse CI or Drone.io (maybe)
- [ ] improve msgpack performance
- [ ] identify performance bottlenecks

## Contributing

Contributions are welcome.
Check the Issues page for ideas of what to work on.
Please add (unit) tests checking the code you are changing/adding.
Before creating a pull request please run the following script,
which performs some automated checks on your code for errors, warning, formatting mistakes, and security vulnerabilities:

```shell
./checks.sh
```

## License

Released under the [MIT License](LICENSE).
