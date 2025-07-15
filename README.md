# Supra Python SDK

[![Discord][discord-image]][discord-url]
[![PyPI Package Version][pypi-image-version]][pypi-url]
[![PyPI Package Downloads][pypi-image-downloads]][pypi-url]

This provides basic functionalities to interact with [Supra](https:/github.com/supra-labs/supra-core/). Get started [here](https://supra.dev/guides/system-integrators-guide/#getting-started).

Currently, this is still in development and may not be suitable for production purposes.

Note: The sync client is deprecated, please only start new projects using the async client. Feature contributions to the sync client will be rejected.

## Requirements

This SDK uses [Poetry](https://python-poetry.org/docs/#installation) for packaging and dependency management:

```
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## Run and Test SDK

Must have access to localnet (smr-moonshot)

```bash
cd remote_env/
make killall
./local_test.sh -n -t daemon
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

<!-- ## E2E testing and Using the Supra CLI -->
<!---->
<!-- - Download and install the [Supra CLI](https://supra.dev/tools/supra-cli/use-cli/running-a-local-network). -->
<!-- - Set the environment variable `SUPRA_CLI_PATH` to the full path of the CLI. -->
<!-- - Retrieve the [Supra Core Github Repo](https://github.com/supra-labs/supra-core) (git clone https://github.com/supra-labs/supra-core) -->
<!-- - Set the environment variable `SUPRA_CORE_REPO` to the full path of the Repository. -->
<!-- - `make integration_test` -->
<!---->

<!-- You can do this a bit more manually by: -->
<!---->
<!-- First, run a local testnet (run this from the root of supra-core): -->
<!---->
<!-- ```bash -->
<!-- supra node run-local-testnet --force-restart --assume-yes --with-indexer-api -->
<!-- ``` -->

<!-- Next, tell the end-to-end tests to talk to this locally running testnet: -->
<!---->
<!-- ```bash -->
<!-- export SUPRA_CORE_REPO="/path/to/repo" -->
<!-- export SUPRA_FAUCET_URL="http://127.0.0.1:8081" -->
<!-- export SUPRA_INDEXER_URL="http://127.0.0.1:8090/v1/graphql" -->
<!-- export SUPRA_NODE_URL="http://127.0.0.1:8080/v1" -->
<!-- ``` -->
<!---->
<!-- Finally run the tests: -->

> [!NOTE]
> The Python SDK does not require the Indexer, if you would prefer to test without it, unset or do not set the environmental variable `SUPRA_INDEXER_URL` and exclude `--with-indexer-api` from running the supra node software.

## Autoformatting

```bash
make fmt
```

## Autolinting

```bash
make lint
```

## Package Publishing

- Download the [Supra CLI](https://supra.dev/tools/supra-cli/install-cli/).
- Set the environment variable `SUPRA_CLI_PATH` to the full path of the CLI.
- `poetry run python -m supra_sdk.cli` and set the appropriate command-line parameters

## Semantic versioning

This project follows [semver](https://semver.org/) as closely as possible

[repo]: https://github.com/supra-labs/supra-core
[pypi-image-version]: https://img.shields.io/pypi/v/supra-sdk.svg
[pypi-image-downloads]: https://img.shields.io/pypi/dm/supra-sdk.svg
[pypi-url]: https://pypi.org/project/supra-sdk
[discord-image]: https://img.shields.io/discord/945856774056083548?label=Discord&logo=discord&style=flat~~~~
[discord-url]: https://discord.gg/supranetwors
