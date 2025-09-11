# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import time
import unittest
from typing import Any, cast

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.api_types import (
    EventsPagination,
    Pagination,
    PaginationWithOrder,
)
from supra_sdk.async_client import ApiError, ClientConfig, FaucetClient, RestClient
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    EntryFunction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


class TestRestClientEndpointsIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.test_account = Account.generate()
        self.rest_client = RestClient(base_url)
        self.faucet_client = FaucetClient(faucet_url, self.rest_client)

    async def test_account(self):
        account_info = await self.rest_client.account(AccountAddress.from_str("0x1"))
        self.assertEqual(account_info["sequence_number"], 0)
        self.assertEqual(
            account_info["authentication_key"],
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )

    async def test_account_supra_balance(self):
        self.assertEqual(
            await self.rest_client.account_supra_balance(self.test_account.address()),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertGreater(
            await self.rest_client.account_supra_balance(self.test_account.address()),
            0,
        )

    async def test_account_coin_balance(self):
        self.assertEqual(
            await self.rest_client.account_coin_balance(
                self.test_account.address(), "0x1::supra_coin::SupraCoin"
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertGreater(
            await self.rest_client.account_coin_balance(
                self.test_account.address(), "0x1::supra_coin::SupraCoin"
            ),
            0,
        )

    async def test_account_sequence_number(self):
        with self.assertRaisesRegex(
            expected_exception=ApiError,
            expected_regex="Resource not found: 0x1::account::Account",
        ):
            await self.rest_client.account_sequence_number(self.test_account.address())

        await self.faucet_client.faucet(self.test_account.address())
        self.assertEqual(
            await self.rest_client.account_sequence_number(self.test_account.address()),
            0,
        )

    async def test_account_resource(self):
        account_resource = await self.rest_client.account_resource(
            AccountAddress.from_str("0x1"), "0x1::account::Account"
        )
        self.assertEqual(account_resource["type"], "0x1::account::Account")

    async def test_account_resources(self):
        self.assertGreater(
            len(
                (
                    await self.rest_client.account_resources(
                        AccountAddress.from_str("0x1")
                    )
                )[0]
            ),
            1,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_resources(
                        AccountAddress.from_str("0x1"), Pagination(count=10)
                    )
                )[0]
            ),
            10,
        )

    async def test_account_module(self):
        module_abi = (
            await self.rest_client.account_module(
                AccountAddress.from_str("0x1"), "supra_coin"
            )
        )["abi"]
        self.assertEqual(module_abi["address"], "0x1")
        self.assertEqual(module_abi["name"], "supra_coin")

    async def test_account_modules(self):
        self.assertGreater(
            len(
                (
                    await self.rest_client.account_modules(
                        AccountAddress.from_str("0x1")
                    )
                )[0]
            ),
            1,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_modules(
                        AccountAddress.from_str("0x1"), Pagination(count=10)
                    )
                )[0]
            ),
            10,
        )

    async def test_account_transactions(self):
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(self.test_account.address())
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(self.test_account.address())
            ),
            2,
        )
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(
                    self.test_account.address(), PaginationWithOrder(count=1)
                )
            ),
            1,
        )

    async def test_account_coin_transactions(self):
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            1,
        )
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            2,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address(), PaginationWithOrder(count=1)
                    )
                )[0]
            ),
            1,
        )

    async def test_transaction_by_hash(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            (await self.rest_client.transaction_by_hash(tx_hash))["hash"], tx_hash
        )

    async def test_estimate_gas_price(self):
        self.assertListEqual(
            list((await self.rest_client.estimate_gas_price()).keys()),
            ["mean_gas_price", "max_gas_price", "median_gas_price"],
        )

    async def test_transaction_parameters(self):
        self.assertListEqual(
            list((await self.rest_client.transaction_parameters()).keys()),
            ["max_transaction_time_to_live_seconds"],
        )

    async def test_submit_transaction(self):
        await self.faucet_client.faucet(self.test_account.address())
        signed_transaction_payload = await self.create_test_signed_transaction_payload()
        tx_hash = await self.rest_client.submit_transaction(signed_transaction_payload)
        self.assertEqual(
            (await self.rest_client.transaction_by_hash(tx_hash))["hash"], tx_hash
        )

    async def test_simulate_transaction(self):
        await self.faucet_client.faucet(self.test_account.address())
        signed_transaction_payload = await self.create_test_signed_transaction_payload()
        self.assertEqual(
            (await self.rest_client.simulate_transaction(signed_transaction_payload))[
                "status"
            ],
            "Success",
        )

    async def test_view(self):
        self.assertEqual(
            len(
                await self.rest_client.view("0x1::timestamp::now_microseconds", [], [])
            ),
            1,
        )

    async def test_get_table_item(self):
        response = await self.rest_client.get_table_item(
            "0x9115cf36a1bc37ccc0e3d1ceadcb72adddc65b19021dbd0623c06ce039e74fc1",
            "address",
            "u128",
            "0x46ee43b58627dff22544be91ddce928242ede01f52a281da8b372813a683abd6",
        )
        self.assertGreater(
            int(cast(str, response)),
            1,
        )

    async def test_events_by_type(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 1
        )
        self.assertGreater(
            len((await self.rest_client.events_by_type("0x1::coin::DepositEvent"))[0]),
            1,
        )
        block_height = (await self.rest_client.transaction_by_hash(tx_hash))[
            "block_header"
        ]["height"]
        self.assertEqual(
            len(
                (
                    await self.rest_client.events_by_type(
                        "0x1::coin::DepositEvent",
                        EventsPagination(
                            start_height=block_height,
                            end_height=block_height + 1,
                            limit=1,
                        ),
                    )
                )[0]
            ),
            1,
        )

    async def test_latest_block(self):
        self.assertTrue("header" in (await self.rest_client.latest_block()))

    async def test_block_by_hash(self):
        latest_block_hash = (await self.rest_client.latest_block())["header"]["hash"]
        self.assertEqual(
            (await self.rest_client.block_by_hash(latest_block_hash))["header"]["hash"],
            latest_block_hash,
        )

    async def test_block_by_height(self):
        self.assertEqual(
            (await self.rest_client.block_by_height(1))["header"]["height"], 1
        )

    async def test_txs_by_block(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 1
        )
        block_hash = (await self.rest_client.transaction_by_hash(tx_hash))[
            "block_header"
        ]["hash"]
        self.assertTrue(tx_hash in (await self.rest_client.txs_by_block(block_hash)))

    async def create_test_signed_transaction_payload(self) -> SignedTransaction:
        transaction_arguments = [
            TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
            TransactionArgument(1, Serializer.u64),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )
        signed_transaction = await self.rest_client.create_signed_transaction(
            self.test_account, TransactionPayload(transaction_payload)
        )
        return signed_transaction

    async def asyncTearDown(self):
        await self.rest_client.close()
        await self.faucet_client.close()


class TransactionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.sender = Account.generate()

        self.rest_client = RestClient(base_url, ClientConfig(max_gas_amount=10_000))
        self.faucet_client = FaucetClient(faucet_url, self.rest_client)

        faucet_tx_hash = await self.faucet_client.faucet(self.sender.address())
        self.assertIsNotNone(faucet_tx_hash)
        await self.faucet_client.wait_for_faucet(faucet_tx_hash)

    async def asyncTearDown(self):
        await self.rest_client.close()
        await self.faucet_client.close()


class TestSupraAutomationTransactions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.sender = Account.generate()

        self.rest_client = RestClient(base_url, ClientConfig(max_gas_amount=10_000))
        faucet_client = FaucetClient(faucet_url, self.rest_client)

        faucet_tx_hash = await faucet_client.faucet(self.sender.address())
        self.assertIsNotNone(faucet_tx_hash)
        await faucet_client.wait_for_faucet(faucet_tx_hash)

    async def test_automation_registration(self):
        tx_hash = await self.register_test_automation_task()
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                tx_hash, "0x1::automation_registry::AutomationTaskMetaData"
            )
        )

    async def test_cancel_automation_task(self):
        task_registration_tx_hash = await self.register_test_automation_task()
        task_id = int(
            (
                await self._get_event_data_from_tx(
                    task_registration_tx_hash,
                    "0x1::automation_registry::AutomationTaskMetaData",
                )
            )["data"]["task_index"]
        )
        task_cancel_tx_hash = await self.rest_client.cancel_automation_task(
            self.sender, task_id
        )
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                task_cancel_tx_hash, "0x1::automation_registry::TaskCancelled"
            )
        )

    async def test_stop_automation_task(self):
        task_registration_tx_hash = await self.register_test_automation_task()
        task_id = int(
            (
                await self._get_event_data_from_tx(
                    task_registration_tx_hash,
                    "0x1::automation_registry::AutomationTaskMetaData",
                )
            )["data"]["task_index"]
        )
        task_stop_tx_hash = await self.rest_client.stop_automation_tasks(
            self.sender, [task_id]
        )
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                task_stop_tx_hash, "0x1::automation_registry::TasksStopped"
            )
        )

    async def register_test_automation_task(self) -> str:
        automated_function = EntryFunction.natural(
            "0x1::supra_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
                TransactionArgument(1, Serializer.u64),
            ],
        )
        tx_hash = await self.rest_client.register_automation_task(
            self.sender,
            automated_function,
            9,
            100,
            4 * (10**8),
            int(time.time()) + 7200,
            [],
        )
        return tx_hash

    async def _get_event_data_from_tx(
        self, tx_hash: str, event_type: str
    ) -> dict[str, Any] | None:
        tx_data = await self.rest_client.transaction_by_hash(tx_hash)
        for event in tx_data["output"]["Move"]["events"]:
            if event["type"] == event_type:
                return event
        return None

    async def asyncTearDown(self):
        await self.rest_client.close()


class TestFaucetClient(unittest.IsolatedAsyncioTestCase):
    async def test_faucet(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_receiver_1 = Account.generate().address()
        faucet_receiver_2 = Account.generate().address()
        faucet_client = FaucetClient(base_url, RestClient(base_url))
        self.assertEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_1),
            0,
        )
        await faucet_client.faucet(faucet_receiver_1)
        self.assertGreater(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_1),
            0,
        )

        self.assertEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_2),
            0,
        )
        faucet_tx_hash = await faucet_client.faucet(
            faucet_receiver_2, wait_for_faucet=False
        )
        self.assertIsNotNone(faucet_tx_hash)
        faucet_tx_data = await faucet_client.wait_for_faucet(faucet_tx_hash)
        self.assertEqual(faucet_tx_data["status"], "Success")
        self.assertNotEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_2),
            0,
        )
        await faucet_client.close()
