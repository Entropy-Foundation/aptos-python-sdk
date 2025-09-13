# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio

from examples.common import RPC_NODE_URL
from supra_sdk.account import Account
from supra_sdk.bcs import Serializer
from supra_sdk.clients.rest import SupraClient
from supra_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


async def main():
    supra_client = SupraClient(RPC_NODE_URL)
    alice = Account.generate()
    bob = Account.generate()
    sponsor = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")
    print(f"Sponsor account address: {sponsor.address()}")

    await supra_client.faucet(sponsor.address())
    await supra_client.faucet(alice.address())
    await supra_client.faucet(bob.address())

    print("Accounts data before fee payer based transfer transaction")
    print(
        f"Alice sequence number: {await supra_client.account_sequence_number(alice.address())}"
    )
    print(f"Alice: {await supra_client.account_supra_balance(alice.address())}")
    print(f"Bob balance: {await supra_client.account_supra_balance(bob.address())}")
    print(
        f"Sponsor balance: {await supra_client.account_supra_balance(sponsor.address())}"
    )

    transaction_arguments = [
        TransactionArgument(bob.address(), Serializer.struct),
        TransactionArgument(1_000, Serializer.u64),  # Amount to transfer
    ]

    transaction_payload = TransactionPayload(
        EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )
    )
    signed_transaction = await supra_client.create_fee_payer_transaction(
        alice, sponsor, [], transaction_payload
    )
    tx_simulation_result = await supra_client.simulate_transaction(signed_transaction)
    if tx_simulation_result["status"] != "Success":
        raise Exception(
            f"Transaction may fail, simulation result: {tx_simulation_result}"
        )
    print("Transaction succeeded in simulation")

    tx_hash = await supra_client.submit_transaction(signed_transaction)
    print(f"Transaction successfully executed, tx_hash: {tx_hash}")
    print("Accounts data before fee payer based transfer transaction")
    print(
        f"Alice sequence number: {await supra_client.account_sequence_number(alice.address())}"
    )
    print(f"Alice: {await supra_client.account_supra_balance(alice.address())}")
    print(f"Bob balance: {await supra_client.account_supra_balance(bob.address())}")
    print(
        f"Sponsor balance: {await supra_client.account_supra_balance(sponsor.address())}"
    )

    await supra_client.close()


if __name__ == "__main__":
    asyncio.run(main())
