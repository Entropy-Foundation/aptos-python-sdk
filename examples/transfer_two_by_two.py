# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os

import aiofiles

from examples.common import RPC_NODE_URL
from supra_sdk.account import Account
from supra_sdk.clients.rest import SupraClient
from supra_sdk.transactions import Script, ScriptArgument, TransactionPayload


async def main():
    supra_client = SupraClient(RPC_NODE_URL)

    alice = Account.generate()
    bob = Account.generate()
    carol = Account.generate()
    david = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")
    print(f"Carol account address: {carol.address()}")
    print(f"David account address: {david.address()}")

    await supra_client.faucet(alice.address())
    await supra_client.faucet(bob.address())
    await supra_client.faucet(carol.address())
    await supra_client.faucet(david.address())

    alice_balance = await supra_client.account_supra_balance(alice.address())
    bob_balance = await supra_client.account_supra_balance(bob.address())
    carol_balance = await supra_client.account_supra_balance(carol.address())
    david_balance = await supra_client.account_supra_balance(david.address())

    print("\n=== Initial Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")
    print(f"Carol: {carol_balance}")
    print(f"David: {david_balance}")

    path = os.path.dirname(__file__)
    filepath = os.path.join(path, "two_by_two_transfer.mv")
    async with aiofiles.open(filepath, mode="rb") as file:
        code = await file.read()

    script_arguments = [
        ScriptArgument(ScriptArgument.U64, 100),
        ScriptArgument(ScriptArgument.U64, 200),
        ScriptArgument(ScriptArgument.ADDRESS, carol.address()),
        ScriptArgument(ScriptArgument.ADDRESS, david.address()),
        ScriptArgument(ScriptArgument.U64, 50),
    ]

    transaction_payload = TransactionPayload(Script(code, [], script_arguments))
    signed_transaction = await supra_client.create_multi_agent_transaction(
        alice, [bob], transaction_payload
    )
    await supra_client.submit_transaction(signed_transaction)

    alice_balance = await supra_client.account_supra_balance(alice.address())
    bob_balance = await supra_client.account_supra_balance(bob.address())
    carol_balance = await supra_client.account_supra_balance(carol.address())
    david_balance = await supra_client.account_supra_balance(david.address())

    print("\n=== Final Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")
    print(f"Carol: {carol_balance}")
    print(f"David: {david_balance}")

    await supra_client.close()
    await supra_client.close()


if __name__ == "__main__":
    asyncio.run(main())
