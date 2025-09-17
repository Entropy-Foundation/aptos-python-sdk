# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""This translates Supra transactions to and from BCS for signing and submitting to the REST API."""

from __future__ import annotations

import unittest

from supra_sdk import ed25519
from supra_sdk.account_address import AccountAddress
from supra_sdk.authenticator import (
    Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
)
from supra_sdk.bcs import Deserializer, Serializer
from supra_sdk.transactions import (
    AutomationRegistrationParams,
    AutomationRegistrationParamsV1,
    EntryFunction,
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


class Test(unittest.TestCase):
    def test_entry_function(self):
        private_key = ed25519.PrivateKey.random()
        public_key = private_key.public_key()
        account_address = AccountAddress.from_key(public_key)

        another_private_key = ed25519.PrivateKey.random()
        another_public_key = another_private_key.public_key()
        recipient_address = AccountAddress.from_key(another_public_key)

        transaction_arguments = [
            TransactionArgument(recipient_address, Serializer.struct),
            TransactionArgument(5000, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )

        raw_transaction = RawTransaction(
            account_address,
            0,
            TransactionPayload(payload),
            2000,
            0,
            18446744073709551615,
            4,
        )

        authenticator = raw_transaction.sign(private_key)
        signed_transaction = SignedTransaction(raw_transaction, authenticator)
        self.verify_transaction_serialization_and_deserialization(signed_transaction)

    def test_entry_function_with_corpus(self):
        # Define common inputs
        sender_key_input = (
            "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
        )
        receiver_key_input = (
            "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"
        )

        sequence_number_input = 11
        gas_unit_price_input = 1
        max_gas_amount_input = 2000
        expiration_timestamps_secs_input = 1234567890
        chain_id_input = 4
        amount_input = 5000

        # Accounts and crypto
        sender_private_key = ed25519.PrivateKey.from_str(sender_key_input)
        sender_public_key = sender_private_key.public_key()
        sender_account_address = AccountAddress.from_key(sender_public_key)

        receiver_private_key = ed25519.PrivateKey.from_str(receiver_key_input)
        receiver_public_key = receiver_private_key.public_key()
        receiver_account_address = AccountAddress.from_key(receiver_public_key)

        # Generate the transaction locally
        transaction_arguments = [
            TransactionArgument(receiver_account_address, Serializer.struct),
            TransactionArgument(amount_input, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )

        raw_transaction_generated = RawTransaction(
            sender_account_address,
            sequence_number_input,
            TransactionPayload(payload),
            max_gas_amount_input,
            gas_unit_price_input,
            expiration_timestamps_secs_input,
            chain_id_input,
        )

        authenticator = raw_transaction_generated.sign(sender_private_key)
        signed_transaction_generated = SignedTransaction(
            raw_transaction_generated, authenticator
        )
        self.verify_transaction_serialization_and_deserialization(
            signed_transaction_generated
        )

        # Validated corpus
        raw_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a73757072615f636f696e095375707261436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d20296490000000004"
        signed_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a73757072615f636f696e095375707261436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d202964900000000040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200404ffb672206aef488d96715761a198c0f67b6f788f6a671e0c36197ea663a3ee7cf36265eaec4be75806a37ba350925bb4758ce2b7bd0e07a5f7ece49fc784d0f"

        self.verify_transactions_with_corpus(
            raw_transaction_input,
            raw_transaction_generated,
            signed_transaction_input,
            signed_transaction_generated,
        )

    def test_entry_function_multi_agent_with_corpus(self):
        # Define common inputs
        sender_key_input = (
            "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
        )
        receiver_key_input = (
            "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"
        )

        sequence_number_input = 11
        gas_unit_price_input = 1
        max_gas_amount_input = 2000
        expiration_timestamps_secs_input = 1234567890
        chain_id_input = 4

        # Accounts and crypto
        sender_private_key = ed25519.PrivateKey.from_str(sender_key_input)
        sender_public_key = sender_private_key.public_key()
        sender_account_address = AccountAddress.from_key(sender_public_key)

        receiver_private_key = ed25519.PrivateKey.from_str(receiver_key_input)
        receiver_public_key = receiver_private_key.public_key()
        receiver_account_address = AccountAddress.from_key(receiver_public_key)

        # Generate the transaction locally
        transaction_arguments = [
            TransactionArgument(receiver_account_address, Serializer.struct),
            TransactionArgument("collection_name", Serializer.str),
            TransactionArgument("token_name", Serializer.str),
            TransactionArgument(1, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x3::token",
            "direct_transfer_script",
            [],
            transaction_arguments,
        )

        raw_transaction_generated = MultiAgentRawTransaction(
            RawTransaction(
                sender_account_address,
                sequence_number_input,
                TransactionPayload(payload),
                max_gas_amount_input,
                gas_unit_price_input,
                expiration_timestamps_secs_input,
                chain_id_input,
            ),
            [receiver_account_address],
        )

        sender_authenticator = raw_transaction_generated.sign(sender_private_key)
        receiver_authenticator = raw_transaction_generated.sign(receiver_private_key)

        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender_authenticator,
                [(receiver_account_address, receiver_authenticator)],
            )
        )

        signed_transaction_generated = SignedTransaction(
            raw_transaction_generated.inner(), authenticator
        )
        self.verify_transaction_serialization_and_deserialization(
            signed_transaction_generated
        )

        # Validated corpus
        raw_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000305746f6b656e166469726563745f7472616e736665725f7363726970740004202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9100f636f6c6c656374696f6e5f6e616d650b0a746f6b656e5f6e616d65080100000000000000d0070000000000000100000000000000d20296490000000004"
        signed_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000305746f6b656e166469726563745f7472616e736665725f7363726970740004202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9100f636f6c6c656374696f6e5f6e616d650b0a746f6b656e5f6e616d65080100000000000000d0070000000000000100000000000000d20296490000000004020020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040334f8a9bba9897203732d87f6e835f1f7fdea0fcbfea5e90cee187395e6b5643c1e5c09b2f32c610200d5da46b3aefc7a69ac4fd06a2fb9172ca8c2785252303012d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9010020aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab40d4333493740ef2df40de4cd86fa51fc1f115e19cc806490be902323af6deb047936bdec7233dae2eeadd0618bceab7472875cbfa8b9ad0433eb145b0c2463606"

        self.verify_transactions_with_corpus(
            raw_transaction_input,
            raw_transaction_generated.inner(),
            signed_transaction_input,
            signed_transaction_generated,
        )

    def test_fee_payer(self):
        sender_private_key = ed25519.PrivateKey.random()
        fee_payer_private_key = ed25519.PrivateKey.random()
        sender_address = AccountAddress.from_key(sender_private_key.public_key())
        fee_payer_address = AccountAddress.from_key(fee_payer_private_key.public_key())

        payload = EntryFunction.natural(
            "0x1::supra_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )
        raw_transaction = RawTransaction(
            sender_address,
            1,
            TransactionPayload(payload),
            200000,
            100,
            1697670723,
            1,
        )

        # Create fee payer raw transaction
        fee_payer_raw_txn = FeePayerRawTransaction(
            raw_transaction, [], fee_payer_address
        )

        # Sign with both accounts
        sender_account_auth = fee_payer_raw_txn.sign(sender_private_key)
        fee_payer_account_auth = fee_payer_raw_txn.sign(fee_payer_private_key)

        # Create fee payer authenticator
        transaction_authenticator = Authenticator(
            FeePayerAuthenticator(
                sender_account_auth, [], (fee_payer_address, fee_payer_account_auth)
            )
        )
        signed_transaction = SignedTransaction(
            raw_transaction, transaction_authenticator
        )
        self.verify_transaction_serialization_and_deserialization(signed_transaction)

    def test_automation_registration(self):
        sender_private_key = ed25519.PrivateKey.random()
        sender_address = AccountAddress.from_key(sender_private_key.public_key())

        automated_entry_function_payload = EntryFunction.natural(
            "0x1::supra_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )
        payload = AutomationRegistrationParams(
            AutomationRegistrationParamsV1(
                automated_entry_function_payload,
                500,
                100,
                1000000,
                1697670823,
                [],
            )
        )
        raw_transaction = RawTransaction(
            sender_address,
            1,
            TransactionPayload(payload),
            200000,
            100,
            1697670723,
            1,
        )

        authenticator = raw_transaction.sign(sender_private_key)
        signed_transaction = SignedTransaction(raw_transaction, authenticator)
        self.verify_transaction_serialization_and_deserialization(signed_transaction)

    def verify_transaction_serialization_and_deserialization(
        self, signed_transaction: SignedTransaction
    ):
        self.assertTrue(signed_transaction.verify())

        # Here we are verifying serialization and deserialization process.
        serializer = Serializer()
        signed_transaction.serialize(serializer)
        serialized_signed_transaction = serializer.output()

        deserializer = Deserializer(serialized_signed_transaction)
        deserialized_signed_txn = deserializer.struct(SignedTransaction)
        self.assertTrue(deserialized_signed_txn.verify())

        serializer = Serializer()
        signed_transaction.serialize(serializer)
        self.assertEqual(serialized_signed_transaction, serializer.output())

    def verify_transactions_with_corpus(
        self,
        raw_transaction_input: str,
        raw_transaction_generated: RawTransaction,
        signed_transaction_input: str,
        signed_transaction_generated: SignedTransaction,
    ):
        # Produce serialized generated transactions
        ser = Serializer()
        ser.struct(raw_transaction_generated)
        raw_transaction_generated_bytes = ser.output().hex()

        ser = Serializer()
        ser.struct(signed_transaction_generated)
        signed_transaction_generated_bytes = ser.output().hex()

        # Verify the RawTransaction
        self.assertEqual(raw_transaction_input, raw_transaction_generated_bytes)
        raw_transaction = RawTransaction.deserialize(
            Deserializer(bytes.fromhex(raw_transaction_input))
        )
        self.assertEqual(raw_transaction_generated, raw_transaction)

        # Verify the SignedTransaction
        self.assertEqual(signed_transaction_input, signed_transaction_generated_bytes)
        signed_transaction = SignedTransaction.deserialize(
            Deserializer(bytes.fromhex(signed_transaction_input))
        )

        self.assertEqual(signed_transaction.transaction, raw_transaction)
        self.assertTrue(signed_transaction.verify())
