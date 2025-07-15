# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.authenticator import Authenticator, FeePayerAuthenticator
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag

from .common import FAUCET_URL, NODE_URL


async def main():
    # :!:>section_1
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)  # <:!:section_1

    # :!:>section_2
    alice = Account.generate()
    bob = Account.generate()
    sponsor = Account.generate()  # <:!:section_2

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")
    print(f"Sponsor: {sponsor.address()}")

    # :!:>section_3
    # Default: 500_000_000
    sponsor_fund_response = await faucet_client.faucet(sponsor.address())
    alice_fund_response = await faucet_client.faucet(alice.address())
    bob_fund_response = await faucet_client.faucet(bob.address())

    # Wait for all faucet transactions to complete
    await asyncio.gather(
        rest_client.wait_for_transaction(sponsor_fund_response["Accepted"]),
        rest_client.wait_for_transaction(alice_fund_response["Accepted"]),
        rest_client.wait_for_transaction(bob_fund_response["Accepted"]),
    )

    print("\n=== Initial Data ===")
    # :!:>section_4
    alice_sequence_number = await rest_client.account_sequence_number(alice.address())

    sponsor_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{sponsor.address().__str__()}"],
    }

    bob_data = {
        "function": "0x1::coin::balance",
        "type_arguments": ["0x1::supra_coin::SupraCoin"],
        "arguments": [f"{bob.address().__str__()}"],
    }

    bob_balance = await rest_client.account_balance(bob_data)
    sponsor_balance = await rest_client.account_balance(sponsor_data)
    print(f"Alice sequence number: {alice_sequence_number}")
    print(f"Bob balance: {bob_balance}")
    print(f"Sponsor balance: {sponsor_balance}")  # <:!:section_4

    # Have Alice give Bob 1_000 coins via a sponsored transaction
    # :!:>section_5
    transaction_arguments = [
        TransactionArgument(bob.address(), Serializer.struct),
        TransactionArgument(1_000, Serializer.u64),  # Amount to transfer
    ]

    supra_coin_type = TypeTag(
        StructTag(AccountAddress.from_str("0x1"), "supra_coin", "SupraCoin", [])
    )

    payload = EntryFunction.natural(
        "0x1::coin",
        "transfer",
        [supra_coin_type],
        transaction_arguments,
    )

    raw_transaction = await rest_client.create_bcs_transaction(
        alice, TransactionPayload(payload), alice_sequence_number
    )
    fee_payer_transaction = FeePayerRawTransaction(raw_transaction, [], None)
    sender_authenticator = alice.sign_transaction(fee_payer_transaction)
    fee_payer_transaction = FeePayerRawTransaction(
        raw_transaction, [], sponsor.address()
    )
    sponsor_authenticator = sponsor.sign_transaction(fee_payer_transaction)
    fee_payer_authenticator = FeePayerAuthenticator(
        sender_authenticator, [], (sponsor.address(), sponsor_authenticator)
    )
    signed_transaction = SignedTransaction(
        raw_transaction, Authenticator(fee_payer_authenticator)
    )

    txn_hash = await rest_client.submit_bcs_txn(signed_transaction)
    # :!:>section_6
    await rest_client.wait_for_transaction(txn_hash)  # <:!:section_6

    print("\n=== Final Data ===")
    alice_sequence_number = rest_client.account_sequence_number(alice.address())
    bob_balance = rest_client.account_balance(bob_data)
    sponsor_balance = rest_client.account_balance(sponsor_data)
    [alice_sequence_number, bob_balance, sponsor_balance] = await asyncio.gather(
        *[alice_sequence_number, bob_balance, sponsor_balance]
    )
    print(f"Alice sequence number: {alice_sequence_number}")
    print(f"Bob balance: {bob_balance}")
    print(f"Sponsor balance: {sponsor_balance}")  # <:!:section_4

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
