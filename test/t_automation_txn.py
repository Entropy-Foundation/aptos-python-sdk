"""
Test script for automation transaction methods.
This tests register_automation_task, cancel_automation_task, and stop_automation_tasks.
"""

import asyncio
import time
import traceback
import unittest

from aptos_sdk.async_client import Account, ClientConfig, FaucetClient, RestClient
from aptos_sdk.bcs import Serializer


class Test(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """
        https://rpc-testnet.supra.com
        """
        self.base_url = "http://localhost:27001"
        self.faucet_url = "http://localhost:27001"
        self.sender = Account.generate()

        client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=1000000,
        )
        self.client = RestClient(self.base_url, client_config)
        self.faucet = FaucetClient(self.faucet_url, self.client)
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
        # Get account info like TypeScript
        account_info = await self.client.account(self.sender.address())

        try:
            receiver_address = self.sender.address()
            receiver_bytes = receiver_address.address

            amount_serializer = Serializer()
            amount_serializer.u64(1000)
            amount_bytes = amount_serializer.output()

            chain_id = await self.client.chain_id()

            print("Creating automation transaction...")

            # Create serialized automation transaction EXACTLY like TypeScript
            automation_raw_transaction = self.client.create_automation_registration_tx_payload_raw_tx_object(
                sender_addr=self.sender.address(),
                sender_sequence_number=account_info["sequence_number"],
                module_addr="0000000000000000000000000000000000000000000000000000000000000001",
                module_name="supra_account",
                function_name="transfer",
                max_gas_amount=1000000,
                function_type_args=[],
                function_args=[receiver_bytes, amount_bytes],
                automation_max_gas_amount=5000,
                automation_gas_price_cap=100,
                automation_fee_cap_for_epoch=100000000,  # Same as TypeScript
                automation_expiration_timestamp_secs=int(time.time()) + 500,
                automation_aux_data=[],
                chain_id=chain_id,
            )

            print("✓ Automation payload created successfully!")

            # Send using serialized raw transaction like TypeScript
            result = await self.client.send_automation_tx_using_raw_transaction(
                sender=self.sender,
                raw_transaction=automation_raw_transaction,
                enable_transaction_simulation=False,
                enable_wait_for_transaction=True,
            )

            print(f"✓ AUTOMATION REGISTRATION SUCCESSFUL: {result}")
            task_id = 1

        except Exception as e:
            print(f"✗ AUTOMATION REGISTRATION FAILED: {e}")
            task_id = 1
            traceback.print_exc()

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

        await asyncio.sleep(1)

        # Test 3: Stop automation tasks
        print("\n=== Testing stop_automation_tasks ===")

        print("Testing actual stop tasks...")
        try:
            stop_result = await self.client.stop_automation_tasks(
                sender=self.sender,
                task_indexes=[1],
                simulate=False,
            )
            print(f"✓ Stop tasks successful: {stop_result}")
        except Exception as e:
            print(f"✗ Stop tasks failed: {e}")

        print("\n=== All tests completed ===")

    async def test_automation_transactions_simulation(self):
        """Test all automation transaction methods"""
        account_info = await self.client.account(self.sender.address())

        try:
            receiver_address = self.sender.address()
            receiver_bytes = receiver_address.address

            amount_serializer = Serializer()
            amount_serializer.u64(1000)
            amount_bytes = amount_serializer.output()

            chain_id = await self.client.chain_id()

            print("Creating automation transaction...")

            # Create serialized automation transaction EXACTLY like TypeScript
            automation_raw_transaction = self.client.create_automation_registration_tx_payload_raw_tx_object(
                sender_addr=self.sender.address(),
                sender_sequence_number=account_info["sequence_number"],
                module_addr="0000000000000000000000000000000000000000000000000000000000000001",
                module_name="supra_account",
                function_name="transfer",
                max_gas_amount=1000000,
                function_type_args=[],
                function_args=[receiver_bytes, amount_bytes],
                automation_max_gas_amount=5000,
                automation_gas_price_cap=100,
                automation_fee_cap_for_epoch=100000000,  # Same as TypeScript
                automation_expiration_timestamp_secs=int(time.time()) + 500,
                automation_aux_data=[],
                chain_id=chain_id,
            )

            print("✓ Automation payload created successfully!")

            # Send using serialized raw transaction like TypeScript
            result = await self.client.send_automation_tx_using_raw_transaction(
                sender=self.sender,
                raw_transaction=automation_raw_transaction,
                enable_transaction_simulation=False,
                enable_wait_for_transaction=True,
            )

            print(f"✓ AUTOMATION REGISTRATION SUCCESSFUL: {result}")
            task_id = 1

        except Exception as e:
            print(f"✗ AUTOMATION REGISTRATION FAILED: {e}")
            task_id = 1
            traceback.print_exc()

        # Wait a bit
        await asyncio.sleep(1)

        # Test 2: Cancel automation task
        print("\n=== Testing cancel_automation_task ===")

        # Test simulation first
        print("Testing cancellation simulation...")
        try:
            sim_result = await self.client.cancel_automation_task(
                sender=self.sender, task_index=task_id, simulate=True
            )
            print(f"✓ Cancellation simulation successful: {sim_result['hash']}")
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
                task_indexes=[1],
                simulate=True,
            )
            print(f"✓ Stop tasks simulation successful: {sim_result['hash']}")
        except Exception as e:
            print(f"✗ Stop tasks simulation failed: {e}")

        print("\n=== All tests completed ===")
