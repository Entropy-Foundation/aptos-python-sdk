# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.supra_token_client import (
    Collection,
    Object,
    PropertyMap,
    ReadObject,
    SupraTokenClient,
    Token,
)


def get_owner(obj: ReadObject) -> AccountAddress:
    return obj.resources[Object].owner


async def get_collection_data(
    token_client: SupraTokenClient, collection_addr: AccountAddress
) -> dict[str, str]:
    collection = (await token_client.read_object(collection_addr)).resources[Collection]
    return {
        "creator": str(collection.creator),
        "name": str(collection.name),
        "description": str(collection.description),
        "uri": str(collection.uri),
    }


async def get_token_data(
    token_client: SupraTokenClient, token_addr: AccountAddress
) -> dict[str, str]:
    token = (await token_client.read_object(token_addr)).resources[Token]
    return {
        "collection": str(token.collection),
        "description": str(token.description),
        "name": str(token.name),
        "uri": str(token.uri),
        "index": str(token.index),
    }


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    token_client = SupraTokenClient(rest_client)

    alice = Account.generate()
    bob = Account.generate()

    collection_name = "Alice's"
    token_name = "Alice's first token"

    owners = {str(alice.address()): "Alice", str(bob.address()): "Bob"}
    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")

    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())

    print("\n=== Creating Collection and Token ===")

    await token_client.create_collection(
        alice,
        "Alice's simple collection",
        1,
        collection_name,
        "https://supra.com",
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        0,
        1,
    )

    collection_addr = AccountAddress.for_named_collection(
        alice.address(), collection_name
    )

    txn_hash = await token_client.mint_token(
        alice,
        collection_name,
        "Alice's simple token",
        token_name,
        "https://supra.com/img/temp.jpeg",
        PropertyMap([]),
    )

    minted_tokens = await token_client.tokens_minted_from_transaction(txn_hash)
    assert len(minted_tokens) == 1

    collection_data = await get_collection_data(token_client, collection_addr)
    print(
        "\nCollection data: "
        + json.dumps({"address": str(collection_addr), **collection_data}, indent=4)
    )

    token_addr = minted_tokens[0]

    # Check the owner
    obj_resources = await token_client.read_object(token_addr)
    owner = str(get_owner(obj_resources))
    print(f"\nToken owner: {owners[owner]}")
    token_data = await get_token_data(token_client, token_addr)
    print(
        "Token data: "
        + json.dumps(
            {"address": str(token_addr), "owner": owner, **token_data}, indent=4
        )
    )

    # Transfer the token to Bob
    print("\n=== Transferring the token to Bob ===")
    await token_client.transfer_token(
        alice,
        token_addr,
        bob.address(),
    )

    # Read the object owner
    obj_resources = await token_client.read_object(token_addr)
    print(f"Token owner: {owners[str(get_owner(obj_resources))]}")

    # Transfer the token back to Alice
    print("\n=== Transferring the token back to Alice ===")
    txn_hash = await token_client.transfer_token(
        bob,
        token_addr,
        alice.address(),
    )

    # Read the object owner one last time
    obj_resources = await token_client.read_object(token_addr)
    print(f"Token owner: {owners[str(get_owner(obj_resources))]}\n")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
