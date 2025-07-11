# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import time

from supra_sdk.account import Account
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.authenticator import Authenticator, Ed25519Authenticator
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    EntryFunction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag

from .common import FAUCET_URL, NODE_URL


async def main():
    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice = Account.generate()
    bob = Account.generate()

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    await faucet_client.faucet(alice.address())
    time.sleep(5)

    payload = EntryFunction.natural(
        "0x1::coin",
        "transfer",
        [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
        [
            TransactionArgument(bob.address(), Serializer.struct),
            TransactionArgument(100_000, Serializer.u64),
        ],
    )
    transaction = await rest_client.create_bcs_transaction(
        alice, TransactionPayload(payload)
    )

    # Create a broken signature for simulation
    broken_signature = alice.sign(b"wrong_data_to_break_signature")

    ed25519_auth = Ed25519Authenticator(
        public_key=alice.public_key(), signature=broken_signature
    )
    authenticator = Authenticator(ed25519_auth)
    signed_transaction = SignedTransaction(transaction, authenticator)

    print("\n=== Simulate before creating Bob's Account ===")
    output = await rest_client.simulate_bcs_txn(signed_transaction)

    vm_status = output["output"]["Move"]["vm_status"]
    assert "Move abort" in vm_status, f"Expected CoinStore error, got: {vm_status}"
    print(json.dumps(output, indent=4, sort_keys=True))

    print("\n=== Simulate after creating Bob's Account ===")
    await faucet_client.faucet(bob.address())
    time.sleep(5)

    # Create another transaction with broken signature for second simulation
    transaction2 = await rest_client.create_bcs_transaction(
        alice, TransactionPayload(payload)
    )
    broken_signature2 = alice.sign(b"another_wrong_data")
    ed25519_auth2 = Ed25519Authenticator(
        public_key=alice.public_key(), signature=broken_signature2
    )
    authenticator2 = Authenticator(ed25519_auth2)
    signed_transaction2 = SignedTransaction(transaction2, authenticator2)

    output2 = await rest_client.simulate_bcs_txn(signed_transaction2)
    vm_status2 = output2["output"]["Move"]["vm_status"]
    assert vm_status2 == "Executed successfully", f"Expected success, got: {vm_status2}"
    print(json.dumps(output2, indent=4, sort_keys=True))

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
