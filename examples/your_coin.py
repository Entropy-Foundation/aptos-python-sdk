# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""This example depends on the MoonCoin.move module.

Steps:
    * `cd ~/aptos-core/aptos-move/move-examples/moon_coin`
    * `supra move tool compile --save-metadata --named-addresses MoonCoin=<Alice address from above step>`
    * `python3 -m examples.your_coin <moon_coin_module_dir> <publisher_private_key>`
"""

import asyncio
import os

import aiofiles

from examples.common import RPC_NODE_URL, SUPRA_CORE_PATH
from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.bcs import Serializer
from supra_sdk.clients.api_client import ApiError
from supra_sdk.clients.rest import SupraClient
from supra_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


class CoinClient(SupraClient):
    async def register_coin(self, coin_address: AccountAddress, sender: Account) -> str:
        """Register the receiver account to receive transfers for the new coin."""
        payload = EntryFunction.natural(
            "0x1::managed_coin",
            "register",
            [TypeTag(StructTag.from_str(f"{coin_address}::moon_coin::MoonCoin"))],
            [],
        )
        signed_transaction = await self.create_signed_transaction(
            sender, TransactionPayload(payload)
        )
        return await self.submit_transaction(signed_transaction)

    async def mint_coin(
        self, minter: Account, receiver_address: AccountAddress, amount: int
    ) -> str:
        """Mints the newly created coin to a specified receiver address."""
        payload = EntryFunction.natural(
            "0x1::managed_coin",
            "mint",
            [TypeTag(StructTag.from_str(f"{minter.address()}::moon_coin::MoonCoin"))],
            [
                TransactionArgument(receiver_address, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )
        signed_transaction = await self.create_signed_transaction(
            minter, TransactionPayload(payload)
        )
        return await self.submit_transaction(signed_transaction)

    async def get_balance(
        self,
        coin_address: AccountAddress,
        account_address: AccountAddress,
    ) -> str:
        """Returns the coin balance of the given account"""
        coin_type = f"{coin_address}::moon_coin::MoonCoin"
        return str(await self.account_coin_balance(account_address, coin_type))


async def main():
    alice = Account.generate()
    bob = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")

    supra_client = CoinClient(RPC_NODE_URL)

    await supra_client.faucet(alice.address())
    await supra_client.faucet(bob.address())

    moon_coin_path = f"{SUPRA_CORE_PATH}/aptos-move/move-examples/moon_coin/"
    command = (
        f"supra move tool compile "
        f"--save-metadata "
        f"--package-dir {moon_coin_path} "
        f"--named-addresses MoonCoin={alice.address()!s}"
    )
    print(f"Running supra CLI command: {command}\n")
    process = await asyncio.create_subprocess_exec(*command.split())
    await process.wait()
    assert process.returncode == 0, "supra move tool compile failed"

    module_path = os.path.join(
        moon_coin_path, "build", "Examples", "bytecode_modules", "moon_coin.mv"
    )
    async with aiofiles.open(module_path, "rb") as f:
        module = await f.read()

    metadata_path = os.path.join(
        moon_coin_path, "build", "Examples", "package-metadata.bcs"
    )
    async with aiofiles.open(metadata_path, "rb") as f:
        metadata = await f.read()

    print("\nPublishing MoonCoin package.")
    await supra_client.publish_package(alice, metadata, [module])

    print("\nBob registers the newly created coin so he can receive it from Alice.")
    await supra_client.register_coin(alice.address(), bob)
    balance = await supra_client.get_balance(alice.address(), bob.address())
    print(f"Bob's initial MoonCoin balance: {balance}")

    print("Alice mints Bob some of the new coin.")
    await supra_client.mint_coin(alice, bob.address(), 100)
    balance = await supra_client.get_balance(alice.address(), bob.address())
    print(f"Bob's updated MoonCoin balance: {balance}")

    try:
        maybe_balance = await supra_client.get_balance(alice.address(), alice.address())
    except ApiError:
        maybe_balance = None
    print(f"Bob will transfer to Alice, her balance: {maybe_balance}")
    txn_hash = await supra_client.transfer_coins(
        bob, alice.address(), f"{alice.address()}::moon_coin::MoonCoin", 5
    )
    await supra_client.wait_for_transaction(txn_hash)
    balance = await supra_client.get_balance(alice.address(), alice.address())
    print(f"Alice's updated MoonCoin balance: {balance}")
    balance = await supra_client.get_balance(alice.address(), bob.address())
    print(f"Bob's updated MoonCoin balance: {balance}")


if __name__ == "__main__":
    asyncio.run(main())
