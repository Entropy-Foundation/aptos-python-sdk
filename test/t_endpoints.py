import asyncio
import json
import time
import unittest

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.api_types import (
    AccountAutomatedTxPagination,
    AccountCoinTxPaginationWithOrder,
    AccountPublishedListPagination,
    AccountTxPaginationWithOrder,
    TableItemRequest,
)
from aptos_sdk.async_client import ClientConfig, RestClient
from aptos_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
)
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    ModuleId,
    MoveTransaction,
    RawTransaction,
    SignedTransaction,
    SupraTransaction,
    TransactionPayload,
)


class AccountTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"
        self.test_account = Account.generate()
        self.test_account_address = self.test_account.account_address.__str__()
        self.bad_address = (
            "1ac1a26e27b175ebf3132e255f97182408442bef0879679626211e45f33dbf88"
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)
        self.faucet_client = RestClient(self.faucet_url, self.client_config)
        await self._fund_and_wait_for_account()

    async def _fund_and_wait_for_account(self):
        """Fund the account via faucet and wait for it to be available on-chain"""
        await self.faucet_client.faucet(address=self.test_account.account_address)

        max_retries = 30
        retry_delay = 1.0  # seconds

        for attempt in range(max_retries):
            try:
                _account_info = await self.client.account(
                    account_address=self.test_account.account_address
                )

                print(f"Account funded and available after {attempt + 1} attempts")
                return

            except Exception as e:
                if attempt < max_retries - 1:
                    print(
                        f"Attempt {
                            attempt + 1
                        }: Account not yet available, retrying in {retry_delay}s..."
                    )
                    await asyncio.sleep(retry_delay)
                else:
                    raise Exception(
                        f"Account failed to become available after {
                            max_retries
                        } attempts: {str(e)}"
                    )

    async def test_chain_id(self):
        res = await self.client.chain_id()
        self.assertIsInstance(res, int, "FAIL: ChainId wrong data-type")
        self.assertEqual(res, 255, "FAIL: ChainId value incorrect")

    async def test_account(self):
        # invalid test case
        with self.assertRaises(Exception) as cm:
            await self.client.account(
                account_address=AccountAddress(bytes.fromhex(self.bad_address))
            )
        self.assertIn(self.bad_address, str(cm.exception))

        # valid test case
        res = await self.client.account(
            account_address=self.test_account.account_address
        )
        self.assertIsInstance(res, dict, "FAIL: Account wrong data-type")
        self.assertEqual(
            res["sequence_number"], 0, "FAIL:> New Acocint must have Sequence no. = 0"
        )
        self.assertIsNot(
            len(res["authentication_key"]), 0, "FAIL: Must havve authentication key"
        )

    async def test_account_transaction(self):
        pagination = AccountTxPaginationWithOrder(count=99, start=0, ascending=True)
        res = await self.client.account_transaction(
            account_address=self.test_account.account_address,
            pagination_with_order=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Transaction wrong data-type")

    async def test_account_automated_transaction(self):
        pagination = AccountAutomatedTxPagination(ascending=True)
        res = await self.client.account_automated_transactions(
            address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, tuple, "FAIL: Automated Transaction wrong data-type")

    async def test_coin_transaction(self):
        pagination = AccountCoinTxPaginationWithOrder(ascending=True)
        res = await self.client.coin_transaction(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_resources(self):
        pagination = AccountPublishedListPagination()
        res = await self.client.account_resources(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_modules(self):
        pagination = AccountPublishedListPagination()
        res = await self.client.account_modules(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_specific_resource(self):
        resource_struct_tag = "0x1::account::Account"

        path_param = (
            self.test_account.account_address,
            resource_struct_tag,
        )
        res = await self.client.account_specific_resource(path_param=path_param)
        self.assertIsInstance(res, dict, "fail: automated transaction wrong data-type")
        self.assertEqual(
            res["type"], resource_struct_tag, "FAIL: Wrong Resource Struct tag recvd"
        )

    async def test_account_specific_modules(self):
        """
        Currently `test_account` doesn't have any modules
        """
        pass


class TransactionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"

        self.test_account = Account.generate()
        # self.test_bad_account = Account.generate()
        self.test_signer_account = Account.generate()
        self.test_authenticator_account = Account.generate()
        self.test_account_address = self.test_account.account_address.__str__()[2:]
        # self.test_bad_address = self.test_account.account_address.__str__()[2:]
        self.test_signer_address = self.test_signer_account.account_address.__str__()[
            2:
        ]
        self.test_authenticator_address = (
            self.test_authenticator_account.account_address.__str__()[2:]
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )
        self.client = RestClient(self.base_url, self.client_config)
        self.faucet_client = RestClient(self.faucet_url, self.client_config)

        # Make faucet trnsaction(Will make a test account)
        self.faucet_client = RestClient(self.faucet_url, self.client_config)
        await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_signer_address))
        )
        await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_authenticator_address))
        )
        await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_account_address))
        )

        await asyncio.sleep(5)

    async def test_estimate_gas_price(self):
        res = await self.client.estimate_gas_price()
        self.assertGreater(res["mean_gas_price"], 0, "FAIL: Wrong data recvd")
        self.assertGreater(res["max_gas_price"], 0, "FAIL: Wrong data recvd")
        self.assertGreater(res["median_gas_price"], 0, "FAIL: Wrong data recvd")

    async def test_transaction_parameters(self):
        res = await self.client.transaction_parameters()
        self.assertIsInstance(res, dict, "fail: automated transaction wrong data-type")
        self.assertGreater(
            res["max_transaction_time_to_live_seconds"], 0, "FAIL: Wrong data recvd"
        )

    async def test_submit_txn(self):
        sender = self.test_account
        authenticator_account = self.test_account
        account = await self.client.account(account_address=sender.account_address)
        chain_id = await self.client.chain_id()

        # Debug: Verify the accounts match
        print(f"Sender address: {sender.account_address.__str__()}")
        print(
            f"Authenticator address: {authenticator_account.account_address.__str__()}"
        )
        print(
            f"Do they match? {
                sender.account_address.__str__()
                == authenticator_account.account_address.__str__()
            }"
        )

        # Transaction Construction
        payload = TransactionPayload(
            EntryFunction(
                module=ModuleId(
                    address=AccountAddress.from_str("0x1"),
                    name="coin",
                ),
                function="transfer",
                ty_args=[],
                args=[],
                # args=[
                #     AccountAddress(
                #         bytes.fromhex(self.test_authenticator_address)
                #     ).address,
                #     (1000).to_bytes(8, "little"),
                # ],
            )
        )

        raw_txn = RawTransaction(
            sender=sender.account_address,
            sequence_number=account["sequence_number"],
            payload=payload,
            max_gas_amount=10000,
            gas_unit_price=100,
            expiration_timestamps_secs=int(time.time()) + 600,
            chain_id=chain_id,
        )

        # Create authenticator data for Move transaction
        # hash_data = raw_txn.keyed()
        # serializer = Serializer()
        # raw_txn.serialize(serializer)
        # hash_data = serializer.output()
        #
        # print(f"Raw transaction bytes: {hash_data.hex()}")
        # signature = authenticator_account.sign(hash_data)
        #
        # print(f"Hash data being signed: {hash_data.hex()}")
        # print(f"Hash data length: {len(hash_data)}")

        # Create signature
        # signature = authenticator_account.sign(hash_data)
        account_authenticator = authenticator_account.sign_transaction(raw_txn)
        # Extract based on the AccountAuthenticator structure
        if account_authenticator.variant == AccountAuthenticator.ED25519:
            ed25519_auth = (
                account_authenticator.authenticator
            )  # This is Ed25519Authenticator
            public_key_hex = ed25519_auth.public_key.to_crypto_bytes().hex()
            signature_hex = str(ed25519_auth.signature)

            auth_data = {
                "Ed25519": {
                    "public_key": public_key_hex,
                    "signature": signature_hex,
                }
            }
        else:
            print(f"Unexpected authenticator variant: {account_authenticator.variant}")

        # Use of MoveTransaction
        move_txn = MoveTransaction(
            raw_transaction=raw_txn, authenticator_data=auth_data
        )

        print("Transaction JSON:", json.dumps(move_txn.to_dict(), indent=2))

        res = await self.client.submit_txn(transaction_data=move_txn)
        print(res)

    async def test_submit_bcs_transaction(self):
        sender = self.test_account
        # authenticator_account = self.test_authenticator_account
        authenticator_account = self.test_account
        print(f"Sender address: {sender.account_address}")
        print(f"Authenticator address: {authenticator_account.account_address}")

        account = await self.client.account(account_address=sender.account_address)
        chain_id = await self.client.chain_id()

        print(f"Account sequence number: {account['sequence_number']}")
        print(f"Chain ID: {chain_id}\n")

        serializer = Serializer()

        # Simple transaction payload - transfer function
        payload = TransactionPayload(
            EntryFunction(
                module=ModuleId(
                    address=AccountAddress.from_str("0x1"),
                    name="coin",
                ),
                function="transfer",
                ty_args=[],
                args=[],
                # args=[
                #     AccountAddress(bytes.fromhex(self.test_authenticator)).address,
                #     (1000).to_bytes(8, "little"),
                # ],
            )
        )

        payload.serialize(serializer)
        payload_bytes = serializer.output()
        print(f"Payload bytes length: {len(payload_bytes)}")
        print(f"Payload bytes: {payload_bytes.hex()}")
        print(f"Payload variant byte: {payload_bytes[0]}\n")

        # Validate payload variant
        if payload_bytes[0] > 2:
            print(f"ERROR: Invalid payload variant {payload_bytes[0]} for Supra")
            return

        raw_txn = RawTransaction(
            sender=sender.account_address,
            sequence_number=account["sequence_number"],
            payload=payload,
            max_gas_amount=10000,
            gas_unit_price=100,
            expiration_timestamps_secs=int(time.time()) + 600,
            chain_id=chain_id,
        )

        # Test raw transaction serialization
        raw_serializer = Serializer()
        raw_txn.serialize(raw_serializer)
        raw_bytes = raw_serializer.output()
        print(f"Raw transaction bytes length: {len(raw_bytes)}")
        print(f"Raw transaction bytes: {raw_bytes.hex()}\n")

        raw_txn_keyed = raw_txn.keyed()
        print(f"Raw transaction keyed bytes length: {len(raw_txn_keyed)}")
        print(f"Raw transaction keyed: {raw_txn_keyed.hex()}\n")

        signature = authenticator_account.sign(raw_txn_keyed)
        print("Transaction signed successfully")
        print(f"Signature: {signature}\n")

        ed25519_auth = Ed25519Authenticator(
            public_key=authenticator_account.public_key(), signature=signature
        )
        authenticator = Authenticator(ed25519_auth)

        signed_txn = SignedTransaction(transaction=raw_txn, authenticator=authenticator)

        signed_serializer = Serializer()
        signed_txn.serialize(signed_serializer)
        signed_bytes = signed_serializer.output()
        print("Signed transaction serialized successfully")
        print(f"Signed transaction bytes length: {len(signed_bytes)}")
        print(f"Signed transaction bytes: {signed_bytes.hex()}\n")

        # Wrap in SupraTransaction
        supra_txn = SupraTransaction.create_move_transaction(signed_txn)
        print(f"SupraTransaction created with variant: {supra_txn.variant}\n")

        supra_serializer = Serializer()
        supra_txn.serialize(supra_serializer)
        supra_bytes = supra_serializer.output()
        print(f"SupraTransaction bytes length: {len(supra_bytes)}")
        print(f"SupraTransaction bytes: {supra_bytes.hex()}")
        print(f"SupraTransaction first byte (variant): {supra_bytes[0]}\n")

        try:
            res = await self.client.submit_bcs_txn(transaction_data=supra_bytes)
            print("Transaction submitted successfully!")
            print(f"Transaction hash: {res}")

        except Exception as e:
            print("Transaction submission failed!")
            print(f"Error: {str(e)}")
            print(f"Error type: {type(e).__name__}")

            # Additional debugging for API errors
            if hasattr(e, "response"):
                print(f"Response status: {e.response.status_code}")
                print(f"Response text: {e.response.text}")

        # raw_txn = RawTransaction(
        #     sender=sender,
        #     sequence_number=account["sequence_number"],
        #     payload=payload,
        #     max_gas_amount=10000,
        #     gas_unit_price=100,
        #     expiration_timestamps_secs=int(time.time()) + 600,
        #     chain_id=chain_id,
        # )
        #
        # # Create authenticator
        # signature = authenticator_account.sign(raw_txn.keyed())
        # ed25519_auth = Ed25519Authenticator(
        #     public_key=authenticator_account.public_key(), signature=signature
        # )
        # # account_auth = AccountAuthenticator(ed25519_auth)
        # #
        # # # Use SingleSenderAuthenticator to match Rust SingleSender variant
        # # single_sender_auth = SingleSenderAuthenticator(account_auth)
        # # authenticator = Authenticator(single_sender_auth)
        # authenticator = Authenticator(ed25519_auth)
        #
        # # Create signed transaction
        # signed_txn = SignedTransaction(transaction=raw_txn, authenticator=authenticator)
        #
        # bcs_bytes = signed_txn.bytes()
        # print(f"BCS bytes length: {len(bcs_bytes)}")
        # print(f"First 20 bytes: {bcs_bytes[:20].hex()}")
        # print(f"All bytes: {bcs_bytes.hex()}")
        #
        # # Submit BCS transaction
        # res = await self.client.submit_bcs_transaction(signed_transaction=signed_txn)
        # print(f"Transaction hash: {res}")
        # self.assertIsInstance(res, str, "FAIL: Hash should be string")
        # self.assertGreater(len(res), 0, "FAIL: Hash cannot be empty")


class BlockTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_latest_block(self):
        res = await self.client.latest_block()
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

    async def test_block_info_by_hash(self):
        latest_block = await self.client.latest_block()
        correct_hash = latest_block["header"]["hash"]
        wrong_hash = "0x" + latest_block["header"]["hash"][::-1][:-2]

        # Correct block info
        res = await self.client.block_info_by_hash(block_hash=correct_hash)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

        with self.assertRaises(Exception) as cm:
            res = await self.client.block_info_by_hash(block_hash=wrong_hash)
        self.assertIn(wrong_hash, str(cm.exception))

    async def test_block_by_height(self):
        latest_block = await self.client.latest_block()
        latest_height = latest_block["header"]["height"]
        correct_height = latest_height - 1
        wrong_height = latest_height + 1000

        res = await self.client.block_by_height(height=correct_height)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

        with self.assertRaises(Exception) as cm:
            res = await self.client.block_by_height(height=wrong_height)
        self.assertIn(str(wrong_height), str(cm.exception))

    async def test_txs_by_block(self):
        latest_block = await self.client.latest_block()
        correct_hash = latest_block["header"]["hash"]
        wrong_hash = "0x" + latest_block["header"]["hash"][::-1][:-2]

        # Correct block info
        res = await self.client.txs_by_block(block_hash=correct_hash)
        self.assertIsInstance(res, list, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res[0]), 0, "FAIL: Block hash cannot be empty")

        with self.assertRaises(Exception) as cm:
            res = await self.client.txs_by_block(block_hash=wrong_hash)
        self.assertIn(wrong_hash, str(cm.exception))

    # async def test_latest_consensus_block(self):
    #     res = await self.client.latest_consensus_block()
    #     self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
    #     self.assertGreater(
    #         len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
    #     )


class TablesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"
        self.test_address = (
            "88FBD33F54E1126269769780FEB24480428179F552E2313FBE571B72E62A1CA1"
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

        # Make faucet trnsaction(Will make a test account)
        self.faucet_client = RestClient(self.faucet_url, self.client_config)
        await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )

    async def test_items_by_key(self):
        tir = TableItemRequest(
            key_type="u64",
            value_type="0x1::multisig_voting::Proposal<0x1::governance_proposal::GovernanceProposal>",
            key="12",
        )

        with self.assertRaises(Exception) as cm:
            res = await self.client.table_items_by_key(
                table_handle=AccountAddress(bytes.fromhex(self.test_address)),
                table_item_request=tir,
            )
        self.assertIn(self.test_address.lower(), str(cm.exception))


class ViewTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_view_function(self):
        data = {
            "function": "0x1::timestamp::now_microseconds",
            "type_arguments": [],
            "arguments": [],
        }

        res = await self.client.view_function(data=data)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res["result"][0]), 0, "FAIL: timestamp cannot be 0")


class EventsTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_events_by_type(self):
        event_type = "0x1::coin::CoinDeposit"
        res = await self.client.events_by_type(event_type=event_type)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res["data"]), 0, "FAIL: timestamp cannot be 0")


class FaucetTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.test_address = (
            "88FBD33F54E1126269769780FEB24480428179F552E2313FBE571B72E62A1CA1"
        )

        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_faucet(self):
        res = await self.client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )
        self.assertIsInstance(res, dict, "FAIL: wrong result data-type")
        self.assertGreater(len(res["Accepted"]), 0, "FAIL: Must return a hash")

    async def test_faucet_txn_by_hash(self):
        res = await self.client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )
        hash = res["Accepted"]

        res = await self.client.faucet_transaction_by_hash(hash=hash)
        self.assertIsInstance(res, dict, "FAIL: wrong result data-type")
        self.assertEqual(res["hash"], hash, "FAIL: Hash must be present")
