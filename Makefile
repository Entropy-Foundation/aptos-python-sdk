# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test:
	uv run python -m unittest discover -s supra_sdk/ -p '*.py' -t ..
	uv run behave

test-coverage:
	uv run python -m coverage run -m unittest discover -s supra_sdk/ -p '*.py' -t ..
	uv run python -m coverage report

test-spec:
	uv run behave

fmt:
	uv run ruff format supra_sdk examples

lint:
	uv run ruff check supra_sdk examples

examples:
	uv run python -m examples.automation
	uv run python -m examples.fee_payer_transfer_coin
	uv run python -m examples.multisig
	uv run python -m examples.rotate_key
	uv run python -m examples.simple_nft
	uv run python -m examples.simple_supra_token
	uv run python -m examples.simulate_transfer_coin
	uv run python -m examples.supra_token
	uv run python -m examples.transfer_coin
	uv run python -m examples.transfer_two_by_two
	uv run python -m examples.your_coin

.PHONY: examples fmt lint test
