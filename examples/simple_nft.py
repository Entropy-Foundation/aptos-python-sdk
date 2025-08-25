# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json

from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.supra_tokenv1_client import SupraTokenV1Client

from .common import FAUCET_URL, NODE_URL


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    token_client = SupraTokenV1Client(rest_client)

    alice = Account.generate()
    bob = Account.generate()

    collection_name = "Alice's"
    token_name = "Alice's first token"
    property_version = 0

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")

    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())

    print("\n=== Creating Collection and Token ===")
    await token_client.create_collection(
        alice, collection_name, "Alice's simple collection", "https://supra.com"
    )

    await token_client.create_token(
        alice,
        collection_name,
        token_name,
        "Alice's simple token",
        1,
        "https://supra.dev/img/temp.jpeg",
        0,
    )

    collection_data = await token_client.get_collection(
        alice.address(), collection_name
    )
    print(
        f"Alice's collection: {json.dumps(collection_data, indent=4, sort_keys=True)}"
    )
    balance = await token_client.get_token_balance(
        alice.address(), alice.address(), collection_name, token_name, property_version
    )
    print(f"Alice's token balance: {balance}")
    token_data = await token_client.get_token_data(
        alice.address(), collection_name, token_name, property_version
    )
    print(f"Alice's token data: {json.dumps(token_data, indent=4, sort_keys=True)}")

    print("\n=== Transferring the token to Bob ===")
    await token_client.offer_token(
        alice,
        bob.address(),
        alice.address(),
        collection_name,
        token_name,
        property_version,
        1,
    )
    await token_client.claim_token(
        bob,
        alice.address(),
        alice.address(),
        collection_name,
        token_name,
        property_version,
    )

    alice_balance = token_client.get_token_balance(
        alice.address(), alice.address(), collection_name, token_name, property_version
    )
    bob_balance = token_client.get_token_balance(
        bob.address(), alice.address(), collection_name, token_name, property_version
    )
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice's token balance: {alice_balance}")
    print(f"Bob's token balance: {bob_balance}")

    print("\n=== Transferring the token back to Alice using MultiAgent ===")
    await token_client.direct_transfer_token(
        bob, alice, alice.address(), collection_name, token_name, 0, 1
    )
    alice_balance = token_client.get_token_balance(
        alice.address(), alice.address(), collection_name, token_name, property_version
    )
    bob_balance = token_client.get_token_balance(
        bob.address(), alice.address(), collection_name, token_name, property_version
    )
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice's token balance: {alice_balance}")
    print(f"Bob's token balance: {bob_balance}")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
