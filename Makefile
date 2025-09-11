# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test-unit:
	uv run python -m unittest discover -s tests/unit/ -p 'test_*.py' -t ..

test-spec:
	uv run behave tests/features

test-all: test-spec test-unit

test-coverage:
	uv run python -m coverage run -m unittest discover -s tests/unit/ -p 'test_*.py' -t ..
	uv run python -m coverage report

fmt:
	uv run ruff format supra_sdk tests/unit examples

lint:
	uv run ruff check supra_sdk tests/unit examples

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

.PHONY: test-unit test-spec test-all test-coverage fmt lint examples
