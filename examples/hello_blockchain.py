# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
This example depends on the hello_blockchain.move module having already been published to the destination blockchain.

Steps:
    * `cd ~/aptos-core/aptos-move/move-examples/hello_blockchain`
    * `supra move tool publish --named-addresses hello_blockchain=${your_address_from_supra_init}`
    * `python3 -m examples.hello_blockchain ${your_address_from_supra_init}`
"""

import asyncio
import sys
from typing import Any, Dict, Optional

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.async_client import ApiError, FaucetClient, RestClient
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

from .common import FAUCET_URL, NODE_URL


class HelloBlockchainClient(RestClient):
    async def get_message(
        self, contract_address: AccountAddress, account_address: AccountAddress
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the resource message::MessageHolder::message"""

        resource_type = f"{contract_address}::message::MessageHolder"
        try:
            return await self.account_resource(account_address, resource_type)
        except ApiError as err:
            if "Information not available" not in str(err):
                raise Exception(err)
            return None

    async def set_message(
        self, contract_address: AccountAddress, sender: Account, message: str
    ) -> str:
        """Potentially initialize and set the resource message::MessageHolder::message"""

        transaction_payload = TransactionPayload(
            EntryFunction.natural(
                f"{contract_address}::message",
                "set_message",
                [],
                [TransactionArgument(message, Serializer.str)],
            )
        )
        signed_transaction = await self.create_signed_transaction(
            sender, transaction_payload
        )
        return await self.submit_transaction(signed_transaction)


async def main(contract_address: AccountAddress):
    alice = Account.generate()
    bob = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")

    rest_client = HelloBlockchainClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())

    print("\n=== Testing Alice ===")
    message = await rest_client.get_message(contract_address, alice.address())
    print(f"Initial value: {message}")
    print('Setting the message to "Hello, Blockchain"')
    await rest_client.set_message(contract_address, alice, "Hello, Blockchain")
    message = await rest_client.get_message(contract_address, alice.address())
    print(f"New value: {message}")

    print("\n=== Testing Bob ===")
    message = await rest_client.get_message(contract_address, bob.address())
    print(f"Initial value: {message}")
    print('Setting the message to "Hello, Blockchain"')
    await rest_client.set_message(contract_address, bob, "Hello, Blockchain")
    message = await rest_client.get_message(contract_address, bob.address())
    print(f"New value: {message}")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 2, "Expecting the contract address"
    contract_address = sys.argv[1]

    asyncio.run(main(AccountAddress.from_str(contract_address)))
