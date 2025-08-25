# Supra Python SDK

[![Discord chat](https://img.shields.io/discord/850682587273625661?style=flat-square)](https://discord.gg/supralabs)

The `supra-python-sdk` provides a seamless interface for interacting with the Supra-L1 network. It offers comprehensive support for `move-vm` operations and transactions, enabling developers to both query on-chain data and submit `move-vm` based transactions with ease.

## Requirements

This SDK uses [Poetry](https://python-poetry.org/docs/#installation) for packaging and dependency management:

```bash
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## Run and Test SDK

> Since the Supra-L1 network codebase is not publicly available, the test cases in `async_client.py` uses testnet rpc-url by default. However, if you are an internal contributor with access to the codebase, you can replace the testnet rpc-url with a localnet rpc-url to run the tests with a local network.

Follow to run the local network using `smr-moonshot`:

```bash
cd remote_env/
make killall
./local_test.sh -t daemon -n
```

> Unit tests

```bash
make test
```

> Test coverage

```bash
make test-coverage
```

> Run examples

```bash
make examples
```

## Autoformatting

```bash
make fmt
```

## Autolinting

```bash
make lint
```

## Semantic versioning

This project follows [semver](https://semver.org/) as closely as possible
