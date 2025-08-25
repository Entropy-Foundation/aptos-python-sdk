# SPDX-License-Identifier: Apache-2.0
import asyncio

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.supra_token_client import Object, Property, PropertyMap, SupraTokenClient


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    token_client = SupraTokenClient(rest_client)

    alice = Account.generate()
    bob = Account.generate()

    collection_name = "Alice's"
    token_name = "Alice's first token"

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

    txn_hash = await token_client.mint_token(
        alice,
        collection_name,
        "Alice's simple token",
        token_name,
        "https://supra.com/img/temp.jpeg",
        PropertyMap([Property.string("string", "string value")]),
    )
    minted_tokens = await token_client.tokens_minted_from_transaction(txn_hash)
    assert len(minted_tokens) == 1
    token_addr = minted_tokens[0]

    collection_addr = AccountAddress.for_named_collection(
        alice.address(), collection_name
    )
    collection_data = await token_client.read_object(collection_addr)
    print(f"Alice's collection: {collection_data}")
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    await token_client.add_token_property(
        alice, token_addr, Property.bool("test", False)
    )
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    await token_client.remove_token_property(alice, token_addr, "string")
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    await token_client.update_token_property(
        alice, token_addr, Property.bool("test", True)
    )
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    await token_client.add_token_property(
        alice, token_addr, Property.bytes("bytes", b"\x00\x01")
    )
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    print("\n=== Transferring the Token from Alice to Bob ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob:   {bob.address()}")
    print(f"Token: {token_addr}\n")
    print(f"Owner: {token_data.resources[Object].owner}")
    print("    ...transferring...    ")
    await rest_client.transfer_object(alice, token_addr, bob.address())

    token_data = await token_client.read_object(token_addr)
    print(f"Owner: {token_data.resources[Object].owner}\n")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
