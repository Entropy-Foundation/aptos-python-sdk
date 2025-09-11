# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""This translates Supra transactions to and from BCS for signing and submitting to the REST API."""

from __future__ import annotations

import hashlib
import unittest
from collections.abc import Callable
from typing import Any, Protocol, cast

from supra_sdk import asymmetric_crypto, ed25519
from supra_sdk.account_address import AccountAddress
from supra_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleKeyAuthenticator,
    SingleSenderAuthenticator,
)
from supra_sdk.bcs import Deserializable, Deserializer, Serializable, Serializer
from supra_sdk.type_tag import StructTag, TypeTag


class RawTransactionInternal(Protocol):
    def keyed(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        prehash = bytearray(self.prehash())
        prehash.extend(serializer.output())
        return bytes(prehash)

    def prehash(self) -> bytes: ...

    def serialize(self, serializer: Serializer) -> None: ...

    def sign(self, key: asymmetric_crypto.PrivateKey) -> AccountAuthenticator:
        signature = key.sign(self.keyed())
        if isinstance(signature, ed25519.Signature):
            return AccountAuthenticator(
                Ed25519Authenticator(
                    cast(ed25519.PublicKey, key.public_key()), signature
                )
            )
        return AccountAuthenticator(SingleKeyAuthenticator(key.public_key(), signature))

    def sign_simulated(self, key: asymmetric_crypto.PublicKey) -> AccountAuthenticator:
        if isinstance(key, ed25519.PublicKey):
            return AccountAuthenticator(
                Ed25519Authenticator(key, ed25519.Signature(b"\x00" * 64))
            )
        else:
            raise NotImplementedError()

    def verify(self, key: ed25519.PublicKey, signature: ed25519.Signature) -> bool:
        return key.verify(self.keyed(), signature)


class RawTransactionWithData(RawTransactionInternal, Protocol):
    raw_transaction: RawTransaction

    def inner(self) -> RawTransaction:
        return self.raw_transaction

    def prehash(self) -> bytes:
        hasher = hashlib.sha3_256()
        hasher.update(b"SUPRA::RawTransactionWithData")
        return hasher.digest()


class RawTransaction(Deserializable, RawTransactionInternal, Serializable):
    # Sender's address
    sender: AccountAddress
    # Sequence number of this transaction. This must match the sequence number in the sender's
    # account at the time of execution.
    sequence_number: int
    # The transaction payload, e.g., a script to execute.
    payload: TransactionPayload
    # Maximum total gas to spend for this transaction
    max_gas_amount: int
    # Price to be paid per gas unit.
    gas_unit_price: int
    # Expiration timestamp for this transaction, represented as seconds from the Unix epoch.
    expiration_timestamps_secs: int
    # Chain ID of the Supra network this transaction is intended for.
    chain_id: int

    def __init__(
        self,
        sender: AccountAddress,
        sequence_number: int,
        payload: TransactionPayload,
        max_gas_amount: int,
        gas_unit_price: int,
        expiration_timestamps_secs: int,
        chain_id: int,
    ):
        self.sender = sender
        self.sequence_number = sequence_number
        self.payload = payload
        self.max_gas_amount = max_gas_amount
        self.gas_unit_price = gas_unit_price
        self.expiration_timestamps_secs = expiration_timestamps_secs
        self.chain_id = chain_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RawTransaction):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.sequence_number == other.sequence_number
            and self.payload == other.payload
            and self.max_gas_amount == other.max_gas_amount
            and self.gas_unit_price == other.gas_unit_price
            and self.expiration_timestamps_secs == other.expiration_timestamps_secs
            and self.chain_id == other.chain_id
        )

    def __str__(self):
        return f"""RawTransaction:
    sender: {self.sender}
    sequence_number: {self.sequence_number}
    payload: {self.payload}
    max_gas_amount: {self.max_gas_amount}
    gas_unit_price: {self.gas_unit_price}
    expiration_timestamps_secs: {self.expiration_timestamps_secs}
    chain_id: {self.chain_id}
"""

    def prehash(self) -> bytes:
        hasher = hashlib.sha3_256()
        hasher.update(b"SUPRA::RawTransaction")
        return hasher.digest()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> RawTransaction:
        return RawTransaction(
            AccountAddress.deserialize(deserializer),
            deserializer.u64(),
            TransactionPayload.deserialize(deserializer),
            deserializer.u64(),
            deserializer.u64(),
            deserializer.u64(),
            deserializer.u8(),
        )

    def serialize(self, serializer: Serializer) -> None:
        self.sender.serialize(serializer)
        serializer.u64(self.sequence_number)
        self.payload.serialize(serializer)
        serializer.u64(self.max_gas_amount)
        serializer.u64(self.gas_unit_price)
        serializer.u64(self.expiration_timestamps_secs)
        serializer.u8(self.chain_id)


class MultiAgentRawTransaction(RawTransactionWithData):
    secondary_signers: list[AccountAddress]

    def __init__(
        self, raw_transaction: RawTransaction, secondary_signers: list[AccountAddress]
    ):
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers

    def serialize(self, serializer: Serializer) -> None:
        # This is a type indicator for an enum
        serializer.u8(0)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)


class FeePayerRawTransaction(RawTransactionWithData):
    secondary_signers: list[AccountAddress]
    fee_payer: AccountAddress | None

    def __init__(
        self,
        raw_transaction: RawTransaction,
        secondary_signers: list[AccountAddress],
        fee_payer: AccountAddress | None,
    ):
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(1)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)
        fee_payer = (
            AccountAddress.from_str("0x0") if self.fee_payer is None else self.fee_payer
        )
        serializer.struct(fee_payer)


class TransactionPayload:
    SCRIPT: int = 0
    MODULE_BUNDLE: int = 1
    ENTRY_FUNCTION: int = 2
    MULTISIG: int = 3
    AUTOMATION_REGISTRATION: int = 4

    variant: int
    value: Any

    def __init__(self, payload: Any):
        if isinstance(payload, Script):
            self.variant = TransactionPayload.SCRIPT
        elif isinstance(payload, ModuleBundle):
            self.variant = TransactionPayload.MODULE_BUNDLE
        elif isinstance(payload, EntryFunction):
            self.variant = TransactionPayload.ENTRY_FUNCTION
        elif isinstance(payload, Multisig):
            self.variant = TransactionPayload.MULTISIG
        elif isinstance(payload, AutomationRegistrationParams):
            self.variant = TransactionPayload.AUTOMATION_REGISTRATION
        else:
            raise Exception("Invalid transaction payload type")
        self.value = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionPayload):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self) -> str:
        return self.value.__str__()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> TransactionPayload:
        variant = deserializer.uleb128()

        if variant == TransactionPayload.SCRIPT:
            payload: Any = Script.deserialize(deserializer)
        elif variant == TransactionPayload.MODULE_BUNDLE:
            payload = ModuleBundle.deserialize(deserializer)
        elif variant == TransactionPayload.ENTRY_FUNCTION:
            payload = EntryFunction.deserialize(deserializer)
        elif variant == TransactionPayload.MULTISIG:
            payload = Multisig.deserialize(deserializer)
        elif variant == TransactionPayload.AUTOMATION_REGISTRATION:
            payload = AutomationRegistrationParams.deserialize(deserializer)
        else:
            raise Exception("Invalid transaction payload type")

        return TransactionPayload(payload)

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.value.serialize(serializer)


class ModuleBundle:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ModuleBundle:
        raise NotImplementedError

    def serialize(self, serializer: Serializer) -> None:
        raise NotImplementedError


class Script:
    code: bytes
    ty_args: list[TypeTag]
    args: list[ScriptArgument]

    def __init__(self, code: bytes, ty_args: list[TypeTag], args: list[ScriptArgument]):
        self.code = code
        self.ty_args = ty_args
        self.args = args

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Script:
        code = deserializer.to_bytes()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(ScriptArgument.deserialize)
        return Script(code, ty_args, args)

    def serialize(self, serializer: Serializer) -> None:
        serializer.to_bytes(self.code)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.struct)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Script):
            return NotImplemented
        return (
            self.code == other.code
            and self.ty_args == other.ty_args
            and self.args == other.args
        )

    def __str__(self):
        return f"<{self.ty_args}>({self.args})"


class ScriptArgument:
    U8: int = 0
    U64: int = 1
    U128: int = 2
    ADDRESS: int = 3
    U8_VECTOR: int = 4
    BOOL: int = 5
    U16: int = 6
    U32: int = 7
    U256: int = 8

    variant: int
    value: Any

    def __init__(self, variant: int, value: Any):
        if variant < 0 or variant > 5:
            raise Exception("Invalid variant")

        self.variant = variant
        self.value = value

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ScriptArgument:
        variant = deserializer.u8()
        if variant == ScriptArgument.U8:
            value: Any = deserializer.u8()
        elif variant == ScriptArgument.U16:
            value = deserializer.u16()
        elif variant == ScriptArgument.U32:
            value = deserializer.u32()
        elif variant == ScriptArgument.U64:
            value = deserializer.u64()
        elif variant == ScriptArgument.U128:
            value = deserializer.u128()
        elif variant == ScriptArgument.U256:
            value = deserializer.u256()
        elif variant == ScriptArgument.ADDRESS:
            value = AccountAddress.deserialize(deserializer)
        elif variant == ScriptArgument.U8_VECTOR:
            value = deserializer.to_bytes()
        elif variant == ScriptArgument.BOOL:
            value = deserializer.bool()
        else:
            raise Exception("Invalid variant")
        return ScriptArgument(variant, value)

    def serialize(self, serializer: Serializer) -> None:
        serializer.u8(self.variant)
        if self.variant == ScriptArgument.U8:
            serializer.u8(self.value)
        elif self.variant == ScriptArgument.U16:
            serializer.u16(self.value)
        elif self.variant == ScriptArgument.U32:
            serializer.u32(self.value)
        elif self.variant == ScriptArgument.U64:
            serializer.u64(self.value)
        elif self.variant == ScriptArgument.U128:
            serializer.u128(self.value)
        elif self.variant == ScriptArgument.U256:
            serializer.u256(self.value)
        elif self.variant == ScriptArgument.ADDRESS:
            serializer.struct(self.value)
        elif self.variant == ScriptArgument.U8_VECTOR:
            serializer.to_bytes(self.value)
        elif self.variant == ScriptArgument.BOOL:
            serializer.bool(self.value)
        else:
            raise Exception(f"Invalid ScriptArgument variant {self.variant}")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScriptArgument):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self):
        return f"[{self.variant}] {self.value}"


class EntryFunction:
    module: ModuleId
    function: str
    ty_args: list[TypeTag]
    args: list[bytes]

    def __init__(
        self, module: ModuleId, function: str, ty_args: list[TypeTag], args: list[bytes]
    ):
        self.module = module
        self.function = function
        self.ty_args = ty_args
        self.args = args

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntryFunction):
            return NotImplemented

        return (
            self.module == other.module
            and self.function == other.function
            and self.ty_args == other.ty_args
            and self.args == other.args
        )

    def __str__(self):
        return f"{self.module}::{self.function}::<{self.ty_args}>({self.args})"

    @staticmethod
    def natural(
        module: str,
        function: str,
        ty_args: list[TypeTag],
        args: list[TransactionArgument],
    ) -> EntryFunction:
        module_id = ModuleId.from_str(module)

        byte_args = []
        for arg in args:
            byte_args.append(arg.encode())
        return EntryFunction(module_id, function, ty_args, byte_args)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> EntryFunction:
        module = ModuleId.deserialize(deserializer)
        function = deserializer.str()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(Deserializer.to_bytes)
        return EntryFunction(module, function, ty_args, args)

    def serialize(self, serializer: Serializer) -> None:
        self.module.serialize(serializer)
        serializer.str(self.function)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.to_bytes)


class Multisig:
    multisig_address: AccountAddress
    transaction_payload: MultisigTransactionPayload | None

    def __init__(
        self,
        multisig_address: AccountAddress,
        transaction_payload: MultisigTransactionPayload | None = None,
    ):
        self.multisig_address = multisig_address
        self.transaction_payload = transaction_payload

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Multisig:
        multisig_address = AccountAddress.deserialize(deserializer)
        payload_present = deserializer.bool()
        transaction_payload = None
        if payload_present:
            transaction_payload = MultisigTransactionPayload.deserialize(deserializer)
        return Multisig(multisig_address, transaction_payload)

    def serialize(self, serializer: Serializer) -> None:
        self.multisig_address.serialize(serializer)
        if self.transaction_payload:
            serializer.bool(True)
            self.transaction_payload.serialize(serializer)
        else:
            serializer.bool(False)


class MultisigTransactionPayload:
    ENTRY_FUNCTION: int = 0
    payload_variant: int
    transaction_payload: EntryFunction

    """
    Currently `MultisigTransactionPayload` only supports `EntryFunction` type payload
    """

    def __init__(self, transaction_payload: Any):
        if isinstance(transaction_payload, EntryFunction):
            self.payload_variant = self.ENTRY_FUNCTION
        else:
            raise Exception("Invalid payload type")
        self.transaction_payload = transaction_payload

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultisigTransactionPayload:
        payload_variant = deserializer.uleb128()
        if payload_variant == MultisigTransactionPayload.ENTRY_FUNCTION:
            transaction_payload = EntryFunction.deserialize(deserializer)
        else:
            raise Exception("Invalid payload type")
        return MultisigTransactionPayload(transaction_payload)

    def serialize(self, serializer: Serializer) -> None:
        # As `MultisigTransactionPayload` is an enum at rust layer, We need to define the enum property number.
        # Currently, we only support `EntryFunction` hence we will always choose 0th property of the enum.
        serializer.uleb128(self.payload_variant)
        self.transaction_payload.serialize(serializer)


class AutomationRegistrationParams:
    V1: int = 0

    variant: int
    registration_params: Any

    def __init__(self, registration_params: Any):
        if isinstance(registration_params, AutomationRegistrationParamsV1):
            self.variant = AutomationRegistrationParams.V1
        else:
            raise Exception("Invalid automation registration params type")
        self.registration_params = registration_params

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AutomationRegistrationParams:
        variant = deserializer.uleb128()
        if variant == AutomationRegistrationParams.V1:
            registration_params = AutomationRegistrationParamsV1.deserialize(
                deserializer
            )
            return AutomationRegistrationParams(registration_params)
        else:
            raise Exception("Invalid automation registration params type")

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.registration_params.serialize(serializer)


class AutomationRegistrationParamsV1:
    def __init__(
        self,
        automated_function: EntryFunction,
        max_gas_amount: int,
        gas_price_cap: int,
        automation_fee_cap_for_epoch: int,
        expiration_timestamp_secs: int,
        aux_data: list[bytes],
    ):
        self.automated_function = automated_function
        self.max_gas_amount = max_gas_amount
        self.gas_price_cap = gas_price_cap
        self.automation_fee_cap_for_epoch = automation_fee_cap_for_epoch
        self.expiration_timestamp_secs = expiration_timestamp_secs
        self.aux_data = aux_data

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AutomationRegistrationParamsV1:
        automated_function = EntryFunction.deserialize(deserializer)
        max_gas_amount = deserializer.u64()
        gas_price_cap = deserializer.u64()
        automation_fee_cap_for_epoch = deserializer.u64()
        expiration_timestamp_secs = deserializer.u64()
        aux_data = deserializer.sequence(Deserializer.to_bytes)
        return AutomationRegistrationParamsV1(
            automated_function,
            max_gas_amount,
            gas_price_cap,
            automation_fee_cap_for_epoch,
            expiration_timestamp_secs,
            aux_data,
        )

    def serialize(self, serializer: Serializer) -> None:
        self.automated_function.serialize(serializer)
        serializer.u64(self.max_gas_amount)
        serializer.u64(self.gas_price_cap)
        serializer.u64(self.automation_fee_cap_for_epoch)
        serializer.u64(self.expiration_timestamp_secs)
        serializer.sequence(self.aux_data, Serializer.to_bytes)


class ModuleId:
    address: AccountAddress
    name: str

    def __init__(self, address: AccountAddress, name: str):
        self.address = address
        self.name = name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModuleId):
            return NotImplemented
        return self.address == other.address and self.name == other.name

    def __str__(self) -> str:
        return f"{self.address}::{self.name}"

    @staticmethod
    def from_str(module_id: str) -> ModuleId:
        split = module_id.split("::")
        return ModuleId(AccountAddress.from_str(split[0]), split[1])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> ModuleId:
        addr = AccountAddress.deserialize(deserializer)
        name = deserializer.str()
        return ModuleId(addr, name)

    def serialize(self, serializer: Serializer) -> None:
        self.address.serialize(serializer)
        serializer.str(self.name)


class TransactionArgument:
    value: Any
    encoder: Callable[[Serializer, Any], None]

    def __init__(
        self,
        value: Any,
        encoder: Callable[[Serializer, Any], None],
    ):
        self.value = value
        self.encoder = encoder

    def encode(self) -> bytes:
        ser = Serializer()
        self.encoder(ser, self.value)
        return ser.output()


class SignedTransaction:
    transaction: RawTransaction
    authenticator: Authenticator

    def __init__(
        self,
        transaction: RawTransaction,
        authenticator: AccountAuthenticator | Authenticator,
    ):
        self.transaction = transaction
        if isinstance(authenticator, AccountAuthenticator):
            if (
                authenticator.variant == AccountAuthenticator.ED25519
                or authenticator == AccountAuthenticator.MULTI_ED25519
            ):
                authenticator = Authenticator(authenticator.authenticator)
            else:
                authenticator = Authenticator(SingleSenderAuthenticator(authenticator))

        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedTransaction):
            return NotImplemented
        return (
            self.transaction == other.transaction
            and self.authenticator == other.authenticator
        )

    def __str__(self) -> str:
        return f"Transaction: {self.transaction}Authenticator: {self.authenticator}"

    def bytes(self) -> bytes:
        ser = Serializer()
        ser.struct(self)
        return ser.output()

    def verify(self) -> bool:
        auth = self.authenticator.authenticator
        if isinstance(auth, MultiAgentAuthenticator):
            transaction: RawTransactionInternal = MultiAgentRawTransaction(
                self.transaction, auth.secondary_addresses()
            )
        elif isinstance(auth, FeePayerAuthenticator):
            transaction = cast(
                RawTransactionInternal,
                FeePayerRawTransaction(
                    self.transaction,
                    auth.secondary_addresses(),
                    auth.fee_payer_address(),
                ),
            )
        else:
            transaction = self.transaction
        return self.authenticator.verify(transaction.keyed())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SignedTransaction:
        transaction = RawTransaction.deserialize(deserializer)
        authenticator = Authenticator.deserialize(deserializer)
        return SignedTransaction(transaction, authenticator)

    def serialize(self, serializer: Serializer) -> None:
        self.transaction.serialize(serializer)
        self.authenticator.serialize(serializer)


class SupraTransaction:
    MOVE: int = 1

    variant: int
    value: Any

    def __init__(self, transaction: Any):
        if isinstance(transaction, SignedTransaction):
            self.variant = SupraTransaction.MOVE
        else:
            raise Exception("Invalid supra transaction type")
        self.value = transaction

    def __str__(self) -> str:
        return f"SupraTransaction: {self.value}"

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SupraTransaction:
        variant = deserializer.uleb128()
        if variant == SupraTransaction.MOVE:
            transaction = SignedTransaction.deserialize(deserializer)
        else:
            raise Exception(f"Invalid supra transaction type, found variant: {variant}")
        return SupraTransaction(transaction)

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.value.serialize(serializer)

    def to_bytes(self) -> bytes:
        """Provides BCS serialized bytes"""
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.output()


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
