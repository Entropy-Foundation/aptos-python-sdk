# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.transactions import Script, ScriptArgument, TransactionPayload


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice = Account.generate()
    bob = Account.generate()
    carol = Account.generate()
    david = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")
    print(f"Carol account address: {carol.address()}")
    print(f"David account address: {david.address()}")

    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())
    await faucet_client.faucet(carol.address())
    await faucet_client.faucet(david.address())

    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    carol_balance = await rest_client.account_supra_balance(carol.address())
    david_balance = await rest_client.account_supra_balance(david.address())

    print("\n=== Initial Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")
    print(f"Carol: {carol_balance}")
    print(f"David: {david_balance}")

    path = os.path.dirname(__file__)
    filepath = os.path.join(path, "two_by_two_transfer.mv")
    with open(filepath, mode="rb") as file:
        code = file.read()

    script_arguments = [
        ScriptArgument(ScriptArgument.U64, 100),
        ScriptArgument(ScriptArgument.U64, 200),
        ScriptArgument(ScriptArgument.ADDRESS, carol.address()),
        ScriptArgument(ScriptArgument.ADDRESS, david.address()),
        ScriptArgument(ScriptArgument.U64, 50),
    ]

    transaction_payload = TransactionPayload(Script(code, [], script_arguments))
    signed_transaction = await rest_client.create_multi_agent_transaction(
        alice, [bob], transaction_payload
    )
    await rest_client.submit_transaction(signed_transaction)

    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    carol_balance = await rest_client.account_supra_balance(carol.address())
    david_balance = await rest_client.account_supra_balance(david.address())

    print("\n=== Final Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")
    print(f"Carol: {carol_balance}")
    print(f"David: {david_balance}")

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
