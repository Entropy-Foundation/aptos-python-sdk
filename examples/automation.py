# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import time

from examples.common import RPC_NODE_URL
from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.bcs import Serializer
from supra_sdk.clients.rest import SupraClient, SupraClientConfig
from supra_sdk.transactions import EntryFunction, TransactionArgument


async def main():
    supra_client_config = SupraClientConfig(
        expiration_ttl=300,
        gas_unit_price=100,
        max_gas_amount=100_000,
    )
    supra_client = SupraClient(RPC_NODE_URL, supra_client_config)
    sender = Account.generate()
    print(f"Automation task creator account address: {sender.address()}")

    await supra_client.faucet(sender.address())
    print(f"Faucet on {sender.address()} done")

    print("Registering automation tasK")
    automated_function = EntryFunction.natural(
        "0x1::supra_account",
        "transfer",
        [],
        [
            TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
            TransactionArgument(1, Serializer.u64),
        ],
    )
    task_registration_tx_hash = await supra_client.register_automation_task(
        sender,
        automated_function,
        9,
        100,
        1 * (10**8),
        int(time.time()) + 7200,
        [],
    )

    task_registration_tx_data = await supra_client.transaction_by_hash(
        task_registration_tx_hash
    )
    task_index = None
    print(json.dumps(task_registration_tx_data, indent=4))
    for event in task_registration_tx_data["output"]["Move"]["events"]:
        if event["type"] == "0x1::automation_registry::AutomationTaskMetaData":
            task_index = event["data"]["task_index"]

    if not task_index:
        raise Exception("`task_index` not found in automation registration transaction")
    print(f"Task registered successfully, task_id: {task_index}")

    print(f"Stopping task, task_index: {task_index}")
    await supra_client.stop_automation_tasks(sender, [int(task_index)])
    print(f"Task stopped successfully, task_index: {task_index}")

    await supra_client.close()


if __name__ == "__main__":
    asyncio.run(main())
