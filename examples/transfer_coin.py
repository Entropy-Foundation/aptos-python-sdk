# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)  # <:!:section_1

    alice = Account.generate()
    bob = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")

    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())

    print("\n=== Initial Balances ===")
    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    # Have Alice give Bob 1_000 coins
    await rest_client.transfer_supra_coin(alice, bob.address(), 1_000)

    print("\n=== Intermediate Balances ===")
    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    # Have Alice give Bob another 1_000 coins using BCS
    await rest_client.transfer_supra_coin(alice, bob.address(), 1_000)

    print("\n=== Final Balances ===")
    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
