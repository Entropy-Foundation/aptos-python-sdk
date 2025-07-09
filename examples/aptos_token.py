# SPDX-License-Identifier: Apache-2.0
import asyncio
import time

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.aptos_token_client import AptosTokenClient, Object, Property, PropertyMap
from aptos_sdk.async_client import FaucetClient, RestClient

from .common import FAUCET_URL, NODE_URL


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)
    token_client = AptosTokenClient(rest_client)
    alice = Account.generate()
    bob = Account.generate()

    collection_name = "Alice's"
    token_name = "Alice's first token"

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    bob_fund = faucet_client.faucet(bob.address())  # Default: 500000000
    alice_fund = faucet_client.faucet(alice.address())  # Default: 500000000
    await asyncio.gather(*[bob_fund, alice_fund])
    time.sleep(5)

    print("\n=== Initial Coin Balances ===")
    alice_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{alice.address().__str__()}"],
    }

    bob_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{bob.address().__str__()}"],
    }

    alice_balance = rest_client.account_balance(alice_data)
    bob_balance = rest_client.account_balance(bob_data)
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    print("\n=== Creating Collection and Token ===")

    txn_hash = await token_client.create_collection(
        alice,
        "Alice's simple collection",
        1,
        collection_name,
        "https://aptos.dev",
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
    await rest_client.wait_for_transaction(txn_hash)

    # This is a hack, once we add support for reading events or indexer, this will be easier
    resource_struct_tag = "0x1::account::Account"
    path_param = (
        alice.address(),
        resource_struct_tag,
    )

    resp = await rest_client.account_specific_resource(path_param=path_param)
    int(resp["data"]["guid_creation_num"])

    txn_hash = await token_client.mint_token(
        alice,
        collection_name,
        "Alice's simple token",
        token_name,
        "https://aptos.dev/img/nyan.jpeg",
        PropertyMap([Property.string("string", "string value")]),
    )
    await rest_client.wait_for_transaction(txn_hash)

    minted_tokens = await token_client.tokens_minted_from_transaction(txn_hash)
    time.sleep(5)
    assert len(minted_tokens) == 1
    token_addr = minted_tokens[0]

    collection_addr = AccountAddress.for_named_collection(
        alice.address(), collection_name
    )
    collection_data = await token_client.read_object(collection_addr)
    print(f"Alice's collection: {collection_data}")
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    txn_hash = await token_client.add_token_property(
        alice, token_addr, Property.bool("test", False)
    )
    await rest_client.wait_for_transaction(txn_hash)
    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")
    txn_hash = await token_client.remove_token_property(alice, token_addr, "string")
    await rest_client.wait_for_transaction(txn_hash)

    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")
    txn_hash = await token_client.update_token_property(
        alice, token_addr, Property.bool("test", True)
    )
    await rest_client.wait_for_transaction(txn_hash)

    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")
    txn_hash = await token_client.add_token_property(
        alice, token_addr, Property.bytes("bytes", b"\x00\x01")
    )
    await rest_client.wait_for_transaction(txn_hash)

    token_data = await token_client.read_object(token_addr)
    print(f"Alice's token: {token_data}")

    print("\n=== Transferring the Token from Alice to Bob ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob:   {bob.address()}")
    print(f"Token: {token_addr}\n")
    print(f"Owner: {token_data.resources[Object].owner}")
    print("    ...transferring...    ")
    txn_hash = await rest_client.transfer_object(alice, token_addr, bob.address())
    await rest_client.wait_for_transaction(txn_hash)

    token_data = await token_client.read_object(token_addr)
    print(f"Owner: {token_data.resources[Object].owner}\n")

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
