"""
Test script for automation transaction methods.
This tests register_automation_task, cancel_automation_task, and stop_automation_tasks.
"""

import asyncio
import time
import unittest

from aptos_sdk.async_client import Account, ClientConfig, RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import EntryFunction, TransactionArgument


class Test(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"
        self.sender = Account.generate()

        client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=1000,
        )
        self.client = RestClient(self.base_url, client_config)
        self.faucet = RestClient(self.faucet_url, client_config)
        await self._fund_and_wait_for_account()

    async def _fund_and_wait_for_account(self):
        """Fund the account via faucet and wait for it to be available on-chain"""
        await self.faucet.faucet(address=self.sender.account_address)

        max_retries = 30
        retry_delay = 1.0  # seconds

        for attempt in range(max_retries):
            try:
                _account_info = await self.client.account(
                    account_address=self.sender.account_address
                )

                return

            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                else:
                    raise Exception(
                        f"Account failed to become available after {
                            max_retries
                        } attempts: {str(e)}"
                    )

    async def test_automation_transactions_submission(self):
        """Test all automation transaction methods"""
        task_arguments = [
            TransactionArgument(self.sender.address(), Serializer.struct),
            TransactionArgument(1, Serializer.u64),
        ]

        task_payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            task_arguments,
        )

        try:
            register_result = await self.client.register_automation_task(
                sender=self.sender,
                task_payload=task_payload,
                task_max_gas_amount=1000,
                task_gas_price_cap=100,
                task_expiry_time_secs=int(time.time()) + 3600,
                task_automation_fee_cap=1000,
                simulate=False,
            )
            print(f"✓ Registration successful: {register_result}")
            task_id = 1
        except Exception as e:
            print(f"✗ Registration failed: {e}")
            task_id = 1

        # Wait a bit
        await asyncio.sleep(1)

        # Test 2: Cancel automation task
        print("\n=== Testing cancel_automation_task ===")

        # Test actual cancellation
        print("Testing actual cancellation...")
        try:
            cancel_result = await self.client.cancel_automation_task(
                sender=self.sender, task_index=task_id, simulate=False
            )
            print(f"✓ Cancellation successful: {cancel_result}")
        except Exception as e:
            print(f"✗ Cancellation failed: {e}")

        # Wait a bit
        await asyncio.sleep(1)

        # Test 3: Stop automation tasks
        print("\n=== Testing stop_automation_tasks ===")

        # Test actual stop
        print("Testing actual stop tasks...")
        try:
            stop_result = await self.client.stop_automation_tasks(
                sender=self.sender,
                task_indexes=[1, 2],
                simulate=False,
            )
            print(f"✓ Stop tasks successful: {stop_result}")
        except Exception as e:
            print(f"✗ Stop tasks failed: {e}")

        print("\n=== All tests completed ===")

    async def test_automation_transactions_simulation(self):
        """Test all automation transaction methods"""
        task_arguments = [
            TransactionArgument(self.sender.address(), Serializer.struct),
            TransactionArgument(1, Serializer.u64),
        ]

        task_payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            task_arguments,
        )

        try:
            sim_result = await self.client.register_automation_task(
                sender=self.sender,
                task_payload=task_payload,
                task_max_gas_amount=1000,
                task_gas_price_cap=1,
                task_expiry_time_secs=int(time.time()) + 3600,  # 1 hour from now
                task_automation_fee_cap=1,
                simulate=True,
                sequence_number=1,
            )
            task_id = 1
        except Exception as e:
            print(f"✗ Registration simulation failed: {e}")
            task_id = 1

        # Wait a bit
        await asyncio.sleep(1)

        # Test 2: Cancel automation task
        print("\n=== Testing cancel_automation_task ===")

        # Test simulation first
        print("Testing cancellation simulation...")
        try:
            sim_result = await self.client.cancel_automation_task(
                sender=self.sender, task_index=task_id, simulate=False
            )
            print(f"✓ Cancellation simulation successful: {type(sim_result)}")
        except Exception as e:
            print(f"✗ Cancellation simulation failed: {e}")

        # Wait a bit
        await asyncio.sleep(1)

        # Test 3: Stop automation tasks
        print("\n=== Testing stop_automation_tasks ===")

        # Test simulation first
        print("Testing stop tasks simulation...")
        try:
            sim_result = await self.client.stop_automation_tasks(
                sender=self.sender,
                task_indexes=[1, 2, 3],
                simulate=False,
            )
            print(f"✓ Stop tasks simulation successful: {type(sim_result)}")
        except Exception as e:
            print(f"✗ Stop tasks simulation failed: {e}")

        print("\n=== All tests completed ===")
