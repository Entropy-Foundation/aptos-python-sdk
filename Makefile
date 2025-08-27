# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test:
	poetry run python -m unittest discover -s supra_sdk/ -p '*.py' -t ..
	poetry run behave

test-coverage:
	poetry run python -m coverage run -m unittest discover -s supra_sdk/ -p '*.py' -t ..
	poetry run python -m coverage report

test-spec:
	poetry run behave

fmt:
	find ./examples ./supra_sdk ./features . -type f -name "*.py" | xargs poetry run autoflake -i -r --remove-all-unused-imports --remove-unused-variables --ignore-init-module-imports
	poetry run isort supra_sdk examples features
	poetry run black supra_sdk examples features

lint:
	poetry run mypy supra_sdk examples features
	poetry run flake8 supra_sdk examples features

examples:
	poetry run python -m examples.automation
	poetry run python -m examples.fee_payer_transfer_coin
	poetry run python -m examples.multisig
	poetry run python -m examples.rotate_key
	poetry run python -m examples.simple_nft
	poetry run python -m examples.simple_supra_token
	poetry run python -m examples.simulate_transfer_coin
	poetry run python -m examples.supra_token
	poetry run python -m examples.transfer_coin
	poetry run python -m examples.transfer_two_by_two
	poetry run python -m examples.your_coin

.PHONY: examples fmt lint test
