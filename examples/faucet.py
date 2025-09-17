# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import asyncio

from examples.common import FAUCET_URL
from supra_sdk.account import Account
from supra_sdk.clients.rest import SupraClient


async def main():
    supra_client = SupraClient(FAUCET_URL)
    alice = Account.generate()
    bob = Account.generate()

    # Send faucet request + wait for faucet tx execution in single go.
    tx_hash = await supra_client.faucet(alice.address())
    assert tx_hash, "faucet request resolution missed, try again"
    alice_balance = await supra_client.account_supra_balance(alice.address())
    print(
        f"Faucet on {alice.address()} successfully done, tx_hash: {tx_hash}, faucet_amount: {alice_balance}"
    )

    # First send faucet request and then manually wait for faucet tx execution.
    tx_hash = await supra_client.faucet(bob.address(), wait_for_faucet=False)
    assert tx_hash, "faucet request resolution missed, try again"
    await supra_client.wait_for_faucet(tx_hash)
    bob_balance = await supra_client.account_supra_balance(bob.address())
    print(
        f"Faucet on {bob.address()} successfully done, tx_hash: {tx_hash}, faucet_amount: {bob_balance}"
    )

    await supra_client.close()


if __name__ == "__main__":
    asyncio.run(main())
