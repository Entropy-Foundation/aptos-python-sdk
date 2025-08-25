# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio

from examples.common import FAUCET_URL, NODE_URL
from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice = Account.generate()
    bob = Account.generate()
    sponsor = Account.generate()

    print(f"Alice account address: {alice.address()}")
    print(f"Bob account address: {bob.address()}")
    print(f"Sponsor account address: {sponsor.address()}")

    await faucet_client.faucet(sponsor.address())
    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())

    print("Accounts data before fee payer based transfer transaction")
    print(
        f"Alice sequence number: {await rest_client.account_sequence_number(alice.address())}"
    )
    print(f"Alice: {await rest_client.account_supra_balance(alice.address())}")
    print(f"Bob balance: {await rest_client.account_supra_balance(bob.address())}")
    print(
        f"Sponsor balance: {await rest_client.account_supra_balance(sponsor.address())}"
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
    signed_transaction = await rest_client.create_fee_payer_transaction(
        alice, sponsor, [], transaction_payload
    )
    tx_simulation_result = await rest_client.simulate_transaction(signed_transaction)
    if tx_simulation_result["status"] != "Success":
        raise Exception(
            f"Transaction may fail, simulation result: {tx_simulation_result}"
        )
    print("Transaction succeeded in simulation")

    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"Transaction successfully executed, tx_hash: {tx_hash}")
    print("Accounts data before fee payer based transfer transaction")
    print(
        f"Alice sequence number: {await rest_client.account_sequence_number(alice.address())}"
    )
    print(f"Alice: {await rest_client.account_supra_balance(alice.address())}")
    print(f"Bob balance: {await rest_client.account_supra_balance(bob.address())}")
    print(
        f"Sponsor balance: {await rest_client.account_supra_balance(sponsor.address())}"
    )

    await rest_client.close()
    await faucet_client.close()


if __name__ == "__main__":
    asyncio.run(main())
