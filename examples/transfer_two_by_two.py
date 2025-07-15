# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os

from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.transactions import (
    Script,
    ScriptArgument,
    TransactionPayload,
)

from .common import FAUCET_URL, NODE_URL


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice = Account.generate()
    bob = Account.generate()
    carol = Account.generate()
    david = Account.generate()

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")
    print(f"Carol: {carol.address()}")
    print(f"David: {david.address()}")

    alice_fund_resp = await faucet_client.faucet(alice.address())
    bob_fund_resp = await faucet_client.faucet(bob.address())
    carol_fund_resp = await faucet_client.faucet(carol.address())
    david_fund_resp = await faucet_client.faucet(david.address())
    await asyncio.gather(
        rest_client.wait_for_transaction(alice_fund_resp["Accepted"]),
        rest_client.wait_for_transaction(bob_fund_resp["Accepted"]),
        rest_client.wait_for_transaction(carol_fund_resp["Accepted"]),
        rest_client.wait_for_transaction(david_fund_resp["Accepted"]),
    )

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

    carol_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{carol.address().__str__()}"],
    }

    david_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{david.address().__str__()}"],
    }

    alice_balance = rest_client.account_balance(alice_data)
    bob_balance = rest_client.account_balance(bob_data)
    carol_balance = rest_client.account_balance(carol_data)
    david_balance = rest_client.account_balance(david_data)
    [alice_balance, bob_balance, carol_balance, david_balance] = await asyncio.gather(
        *[alice_balance, bob_balance, carol_balance, david_balance]
    )

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

    payload = TransactionPayload(Script(code, [], script_arguments))
    signed_transaction = await rest_client.create_multi_agent_bcs_transaction(
        alice, [bob], payload
    )
    txn_hash = await rest_client.submit_bcs_txn(signed_transaction)
    await rest_client.wait_for_transaction(txn_hash)

    alice_balance = rest_client.account_balance(alice_data)
    bob_balance = rest_client.account_balance(bob_data)
    carol_balance = rest_client.account_balance(carol_data)
    david_balance = rest_client.account_balance(david_data)
    [alice_balance, bob_balance, carol_balance, david_balance] = await asyncio.gather(
        *[alice_balance, bob_balance, carol_balance, david_balance]
    )

    print("\n=== Final Balances ===")
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")
    print(f"Carol: {carol_balance}")
    print(f"David: {david_balance}")

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
