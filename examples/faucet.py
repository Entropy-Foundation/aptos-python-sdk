# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import asyncio

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.async_client import ClientConfig, FaucetClient, RestClient


async def main():
    client_config = ClientConfig(
        expiration_ttl=300,
        gas_unit_price=100,
        max_gas_amount=100_000,
    )
    rest_client = RestClient(NODE_URL, client_config)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    alice = Account.generate()
    bob = Account.generate()

    # Send faucet request + wait for faucet tx execution in single go.
    tx_hash = await faucet_client.faucet(alice.address())
    assert tx_hash, "faucet request resolution missed, try again"
    alice_balance = await rest_client.account_supra_balance(alice.address())
    print(
        f"Faucet on {alice.address()} successfully done, tx_hash: {tx_hash}, faucet_amount: {alice_balance}"
    )

    # First send faucet request and then manually wait for faucet tx execution.
    tx_hash = await faucet_client.faucet(bob.address(), wait_for_faucet=False)
    assert tx_hash, "faucet request resolution missed, try again"
    await faucet_client.wait_for_faucet(tx_hash)
    bob_balance = await rest_client.account_supra_balance(bob.address())
    print(
        f"Faucet on {bob.address()} successfully done, tx_hash: {tx_hash}, faucet_amount: {bob_balance}"
    )

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
