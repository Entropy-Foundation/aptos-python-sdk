# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

"""
This translates Supra transactions to and from BCS for signing and submitting to the REST API.
"""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union, cast

from typing_extensions import Protocol

from . import asymmetric_crypto, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleKeyAuthenticator,
    SingleSenderAuthenticator,
)
from .bcs import Deserializable, Deserializer, Serializable, Serializer
from .type_tag import StructTag, TypeTag


class RawTransactionInternal(Protocol):
    def keyed(self) -> bytes:
        ser = Serializer()
        self.serialize(ser)
        prehash = bytearray(self.prehash())
        prehash.extend(ser.output())
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
        elif isinstance(key, secp256k1_ecdsa.PublicKey):
            return AccountAuthenticator(
                SingleKeyAuthenticator(key, secp256k1_ecdsa.Signature(b"\x00" * 64))
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
    secondary_signers: List[AccountAddress]

    def __init__(
        self, raw_transaction: RawTransaction, secondary_signers: List[AccountAddress]
    ):
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers

    def serialize(self, serializer: Serializer) -> None:
        # This is a type indicator for an enum
        serializer.u8(0)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)


class FeePayerRawTransaction(RawTransactionWithData):
    secondary_signers: List[AccountAddress]
    fee_payer: Optional[AccountAddress]

    def __init__(
        self,
        raw_transaction: RawTransaction,
        secondary_signers: List[AccountAddress],
        fee_payer: Optional[AccountAddress],
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
    SCRIPT_FUNCTION: int = 2
    MULTISIG: int = 3
    AUTOMATION: int = 4

    variant: int
    value: Any

    def __init__(self, payload: Any):
        if isinstance(payload, Script):
            self.variant = TransactionPayload.SCRIPT
        elif isinstance(payload, ModuleBundle):
            self.variant = TransactionPayload.MODULE_BUNDLE
        elif isinstance(payload, EntryFunction):
            self.variant = TransactionPayload.SCRIPT_FUNCTION
        elif isinstance(payload, Multisig):
            self.variant = TransactionPayload.MULTISIG
        elif isinstance(payload, TransactionPayloadAutomationRegistration):
            self.variant = TransactionPayload.AUTOMATION
        else:
            raise Exception("Invalid type")
        self.value = payload

    def to_dict(self) -> Dict[str, Any]:
        """Convert payload to dictionary format for SMR transactions"""
        if self.variant in [
            TransactionPayload.SCRIPT,
            TransactionPayload.MODULE_BUNDLE,
            TransactionPayload.SCRIPT_FUNCTION,
            TransactionPayload.MULTISIG,
            TransactionPayload.AUTOMATION,
        ]:
            # return {"variant": self.variant, "value": self.value.to_dict()}
            return self.value.to_dict()
        else:
            raise Exception("Invalid payload type for conversion")

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
        elif variant == TransactionPayload.SCRIPT_FUNCTION:
            payload = EntryFunction.deserialize(deserializer)
        elif variant == TransactionPayload.MULTISIG:
            payload = Multisig.deserialize(deserializer)
        elif variant == TransactionPayload.AUTOMATION:
            payload = TransactionPayloadAutomationRegistration.deserialize(deserializer)
        else:
            raise Exception("Invalid type")

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
    ty_args: List[TypeTag]
    args: List[ScriptArgument]

    def __init__(self, code: bytes, ty_args: List[TypeTag], args: List[ScriptArgument]):
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
    ty_args: List[TypeTag]
    args: List[bytes]

    def __init__(
        self, module: ModuleId, function: str, ty_args: List[TypeTag], args: List[bytes]
    ):
        self.module = module
        self.function = function
        self.ty_args = ty_args
        self.args = args

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": {
                "address": str(self.module.address.__str__()),
                "name": self.module.name,
            },
            "function": self.function,
            "ty_args": [self._type_tag_to_dict(ty_arg) for ty_arg in self.ty_args],
            "args": [arg.hex() for arg in self.args],
        }

    def _type_tag_to_dict(self, type_tag: TypeTag) -> Dict[str, Any]:
        """Convert TypeTag to the JSON structure expected by the server"""
        if hasattr(type_tag, "value") and hasattr(type_tag.value, "address"):
            # It's a StructTag
            struct_tag = type_tag.value
            return {
                "Struct": {
                    "address": str(struct_tag.address),
                    "module": struct_tag.module,
                    "name": struct_tag.name,
                    "type_args": [],
                }
            }
        else:
            # Handle other type tag variants as needed
            return {"Struct": str(type_tag)}

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
        ty_args: List[TypeTag],
        args: List[TransactionArgument],
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
    transaction_payload: MultisigTransactionPayload

    def __init__(
        self,
        multisig_address: AccountAddress,
        transaction_payload: Optional[MultisigTransactionPayload] = None,
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

    def serialize(self, serializer: Serializer):
        self.multisig_address.serialize(serializer)
        serializer.bool(self.transaction_payload is not None)
        if self.transaction_payload is not None:
            self.transaction_payload.serialize(serializer)


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

    def serialize(self, serializer: Serializer):
        # As `MultisigTransactionPayload` is an enum at rust layer, We need to define the enum property number.
        # Currently, we only support `EntryFunction` hence we will always choose 0th property of the enum.
        serializer.uleb128(self.payload_variant)
        self.transaction_payload.serialize(serializer)


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
        authenticator: Union[AccountAuthenticator, Authenticator],
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


@dataclass
class AutomatedTransaction:
    raw_txn: RawTransaction
    authenticator: Authenticator
    block_height: int
    _raw_txn_size: Optional[int] = field(default=None, init=False, repr=False)
    _hash: Optional[bytes] = field(default=None, init=False, repr=False)

    def __eq__(self, other) -> bool:
        if not isinstance(other, AutomatedTransaction):
            return False
        else:
            return (
                self.raw_txn == other.raw_txn
                and self.authenticator == other.authenticator
                and self.block_height == other.block_height
            )

    def __str__(self) -> str:
        return f"""
            AutomatedTransaction:
            raw_txn: {self.raw_txn}
            authenticator: {self.authenticator.__str__()}
        """

    def sender(self) -> AccountAddress:
        return self.raw_txn.sender

    def sequence_number(self) -> int:
        return self.raw_txn.sequence_number

    def chain_id(self) -> int:
        return self.raw_txn.chain_id

    def payload(self) -> TransactionPayload:
        return self.raw_txn.payload

    def max_gas_amount(self) -> int:
        return self.raw_txn.max_gas_amount

    def gas_unit_price(self) -> int:
        return self.raw_txn.gas_unit_price

    def expiration_timestamps_secs(self) -> int:
        return self.raw_txn.expiration_timestamps_secs

    def duration_since(self, base_timestamp: int) -> Optional[int]:
        expiration = self.expiration_timestamps_secs()
        if expiration > base_timestamp:
            return expiration - base_timestamp
        return None

    @property
    def raw_txn_bytes_len(self) -> int:
        if self._raw_txn_size is None:
            serializer = Serializer()
            self.raw_txn.serialize(serializer)
            self._raw_txn_size = len(serializer.output())
        return self._raw_txn_size

    def txn_bytes_len(self):
        serializer = Serializer()
        self.authenticator.serialize(Serializer)
        auth_size = len(serializer.output)
        return self.raw_txn_bytes_len() + auth_size

    @property
    def hash(self) -> bytes:
        if self._hash is None:
            serializer = Serializer()
            self.serialize(serializer)
            self._hash = hashlib.sha3_256(serializer.output()).digest()
        return self._hash

    def serialize(self, s: Serializer) -> None:
        self.raw_txn.serialize(s)
        self.authenticator.serialize(s)
        s.u64(self.block_height)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AutomatedTransaction":
        raw_txn = RawTransaction.deserialize(deserializer)
        authenticator = Authenticator.deserialize(deserializer)
        block_height = deserializer.u64()
        return AutomatedTransaction(raw_txn, authenticator, block_height)


class SupraTransaction:
    SMR: int = 0
    MOVE: int = 1

    variant: int
    value: Union[SignedSmrTransaction, SignedTransaction]

    def __init__(self, transaction: Union[SignedSmrTransaction, SignedTransaction]):
        if (
            hasattr(transaction, "__class__")
            and transaction.__class__.__name__ == "SignedSmrTransaction"
        ):
            self.variant = SupraTransaction.SMR
        elif (
            hasattr(transaction, "__class__")
            and transaction.__class__.__name__ == "SignedTransaction"
        ):
            self.variant = SupraTransaction.MOVE
        else:
            raise Exception("Invalid transaction type for SupraTransaction")

        self.value = transaction

    @staticmethod
    def create_move_transaction(
        signed_transaction: "SignedTransaction",
    ) -> "SupraTransaction":
        """Create a SupraTransaction with Move variant"""
        return SupraTransaction(signed_transaction)

    @staticmethod
    def create_smr_transaction(
        signed_smr_transaction: "SignedSmrTransaction",
    ) -> "SupraTransaction":
        """Create a SupraTransaction with SMR variant"""
        return SupraTransaction(signed_smr_transaction)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SupraTransaction):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self) -> str:
        variant_name = "SMR" if self.variant == SupraTransaction.SMR else "MOVE"
        return f"SupraTransaction::{variant_name}({self.value})"

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.variant)
        self.value.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SupraTransaction":
        variant = deserializer.uleb128()

        if variant == SupraTransaction.SMR:
            transaction = SignedSmrTransaction.deserialize(deserializer)
        elif variant == SupraTransaction.MOVE:
            transaction = SignedTransaction.deserialize(deserializer)
        else:
            raise Exception(f"Invalid SupraTransaction variant: {variant}")

        return SupraTransaction(transaction)

    def bytes(self) -> bytes:
        """Helper method to get serialized bytes"""
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.output()


class SignedSmrTransaction:
    def __init__(self, signer_data: SignerData, transaction: UnsignedSmrTransaction):
        self.signer_data = signer_data
        self.transaction = transaction

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedSmrTransaction):
            return NotImplemented
        return (
            self.signer_data == other.signer_data
            and self.transaction == other.transaction
        )

    def __str__(self) -> str:
        return f"SignedSmrTransaction(signer_data={self.signer_data}, transaction={self.transaction})"

    def serialize(self, serializer: Serializer) -> None:
        self.signer_data.serialize(serializer)
        self.transaction.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SignedSmrTransaction":
        signer_data = SignerData.deserialize(deserializer)
        transaction = UnsignedSmrTransaction.deserialize(deserializer)
        return SignedSmrTransaction(signer_data, transaction)


class SignerData:
    def __init__(self, signer: bytes, signature: bytes):
        self.signer = signer  # PublicKey bytes
        self.signature = signature  # Signature bytes

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignerData):
            return NotImplemented
        return self.signer == other.signer and self.signature == other.signature

    def __str__(self) -> str:
        return (
            f"SignerData(signer={self.signer.hex()}, signature={self.signature.hex()})"
        )

    def serialize(self, serializer: Serializer) -> None:
        # Assuming Ed25519 keys and signature
        serializer.fixed_bytes(self.signer)
        serializer.fixed_bytes(self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SignerData":
        signer = deserializer.fixed_bytes(32)  # Ed25519 public key length
        signature = deserializer.fixed_bytes(64)  # Ed25519 signature length
        return SignerData(signer, signature)


class UnsignedSmrTransaction:
    def __init__(self, header: SmrTransactionHeader, payload: SmrTransactionPayload):
        self.header = header
        self.payload = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnsignedSmrTransaction):
            return NotImplemented
        return self.header == other.header and self.payload == other.payload

    def __str__(self) -> str:
        return f"UnsignedSmrTransaction(header={self.header}, payload={self.payload})"

    def serialize(self, serializer: Serializer) -> None:
        self.header.serialize(serializer)
        self.payload.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "UnsignedSmrTransaction":
        header = SmrTransactionHeader.deserialize(deserializer)
        payload = SmrTransactionPayload.deserialize(deserializer)
        return UnsignedSmrTransaction(header, payload)


class SmrTransactionHeader:
    def __init__(
        self,
        chain_id: int,
        expiration_timestamp: int,
        sender: "AccountAddress",
        sequence_number: int,
        gas_unit_price: int,
        max_gas_amount: int,
    ):
        self.chain_id = chain_id
        self.expiration_timestamp = expiration_timestamp
        self.sender = sender
        self.sequence_number = sequence_number
        self.gas_unit_price = gas_unit_price
        self.max_gas_amount = max_gas_amount

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SmrTransactionHeader):
            return NotImplemented
        return (
            self.chain_id == other.chain_id
            and self.expiration_timestamp == other.expiration_timestamp
            and self.sender == other.sender
            and self.sequence_number == other.sequence_number
            and self.gas_unit_price == other.gas_unit_price
            and self.max_gas_amount == other.max_gas_amount
        )

    def serialize(self, serializer: Serializer) -> None:
        serializer.u64(self.chain_id)
        # Assuming SmrTimestamp is u64
        serializer.u64(self.expiration_timestamp)
        self.sender.serialize(serializer)
        serializer.u64(self.sequence_number)
        serializer.u128(self.gas_unit_price)
        serializer.u64(self.max_gas_amount)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SmrTransactionHeader":
        chain_id = deserializer.u64()
        expiration_timestamp = deserializer.u64()
        sender = AccountAddress.deserialize(deserializer)
        sequence_number = deserializer.u64()
        gas_unit_price = deserializer.u128()
        max_gas_amount = deserializer.u64()
        return SmrTransactionHeader(
            chain_id,
            expiration_timestamp,
            sender,
            sequence_number,
            gas_unit_price,
            max_gas_amount,
        )


class SmrTransactionPayload:
    DKG: int = 0
    ORACLE: int = 1

    def __init__(self, payload_type: int, data: bytes):
        self.payload_type = payload_type
        self.data = data  # Simplified - just store as bytes for now

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SmrTransactionPayload):
            return NotImplemented
        return self.payload_type == other.payload_type and self.data == other.data

    def serialize(self, serializer: Serializer) -> None:
        serializer.uleb128(self.payload_type)
        serializer.bytes(self.data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SmrTransactionPayload":
        payload_type = deserializer.uleb128()
        data = deserializer.bytes()
        return SmrTransactionPayload(payload_type, data)

    @staticmethod
    def create_dkg_payload(data: bytes) -> "SmrTransactionPayload":
        return SmrTransactionPayload(SmrTransactionPayload.DKG, data)

    @staticmethod
    def create_oracle_payload(data: bytes) -> "SmrTransactionPayload":
        return SmrTransactionPayload(SmrTransactionPayload.ORACLE, data)


class MoveTransaction:
    def __init__(self, raw_transaction: RawTransaction, authenticator_data: Dict):
        self.raw_transaction = raw_transaction
        self.authenticator_data = authenticator_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Move": {
                "raw_txn": {
                    "sender": self.raw_transaction.sender.__str__(),
                    "sequence_number": self.raw_transaction.sequence_number,
                    "payload": {
                        "EntryFunction": self.raw_transaction.payload.value.to_dict()
                    },
                    "max_gas_amount": self.raw_transaction.max_gas_amount,
                    "gas_unit_price": self.raw_transaction.gas_unit_price,
                    "expiration_timestamp_secs": self.raw_transaction.expiration_timestamps_secs,
                    "chain_id": self.raw_transaction.chain_id,
                },
                "authenticator": self.authenticator_data,
            }
        }


class AutomationRegistrationParamsV1Data:
    """
    Python equivalent of TypeScript's AutomationRegistrationParamsV1Data
    """

    def __init__(
        self,
        automated_function: EntryFunction,
        max_gas_amount: int,
        gas_price_cap: int,
        automation_fee_cap_for_epoch: int,
        expiration_timestamp_secs: int,
        aux_data: List[bytes],
    ):
        self.automated_function = automated_function
        self.max_gas_amount = max_gas_amount
        self.gas_price_cap = gas_price_cap
        self.automation_fee_cap_for_epoch = automation_fee_cap_for_epoch
        self.expiration_timestamp_secs = expiration_timestamp_secs
        self.aux_data = aux_data

    def serialize(self, serializer: Serializer) -> None:
        """Serialize exactly like TypeScript"""
        self.automated_function.serialize(serializer)
        serializer.u64(self.max_gas_amount)
        serializer.u64(self.gas_price_cap)
        serializer.u64(self.automation_fee_cap_for_epoch)
        serializer.u64(self.expiration_timestamp_secs)
        serializer.sequence(self.aux_data, Serializer.to_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AutomationRegistrationParamsV1Data":
        automated_function = EntryFunction.deserialize(deserializer)
        max_gas_amount = deserializer.u64()
        gas_price_cap = deserializer.u64()
        automation_fee_cap_for_epoch = deserializer.u64()
        expiration_timestamp_secs = deserializer.u64()
        aux_data = deserializer.sequence(Deserializer.to_bytes)
        return AutomationRegistrationParamsV1Data(
            automated_function,
            max_gas_amount,
            gas_price_cap,
            automation_fee_cap_for_epoch,
            expiration_timestamp_secs,
            aux_data,
        )


class AutomationRegistrationParamsV1:
    """
    Python equivalent of TypeScript's AutomationRegistrationParamsV1
    """

    def __init__(self, value: AutomationRegistrationParamsV1Data):
        self.value = value

    def serialize(self, serializer: Serializer) -> None:
        """Serialize V1 variant - first serialize variant index, then data"""
        serializer.u8(0)  # V1 variant index
        self.value.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AutomationRegistrationParamsV1":
        variant = deserializer.u8()
        if variant != 0:
            raise ValueError(f"Unknown AutomationRegistrationParams variant: {variant}")
        value = AutomationRegistrationParamsV1Data.deserialize(deserializer)
        return AutomationRegistrationParamsV1(value)


class TransactionPayloadAutomationRegistration:
    """
    Python equivalent of TypeScript's TransactionPayloadAutomationRegistration
    """

    def __init__(self, value: AutomationRegistrationParamsV1):
        self.value = value

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the automation registration payload"""
        self.value.serialize(serializer)

    @staticmethod
    def deserialize(
        deserializer: Deserializer,
    ) -> "TransactionPayloadAutomationRegistration":
        value = AutomationRegistrationParamsV1.deserialize(deserializer)
        return TransactionPayloadAutomationRegistration(value)


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
        self.assertTrue(signed_transaction.verify())

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
        self.assertTrue(signed_transaction_generated.verify())

        # Validated corpus
        raw_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a73757072615f636f696e095375707261436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d20296490000000004"
        signed_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a73757072615f636f696e095375707261436f696e0002202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9088813000000000000d0070000000000000100000000000000d202964900000000040020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200404ffb672206aef488d96715761a198c0f67b6f788f6a671e0c36197ea663a3ee7cf36265eaec4be75806a37ba350925bb4758ce2b7bd0e07a5f7ece49fc784d0f"

        self.verify_transactions(
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

        # Validated corpus
        raw_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000305746f6b656e166469726563745f7472616e736665725f7363726970740004202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9100f636f6c6c656374696f6e5f6e616d650b0a746f6b656e5f6e616d65080100000000000000d0070000000000000100000000000000d20296490000000004"
        signed_transaction_input = "7deeccb1080854f499ec8b4c1b213b82c5e34b925cf6875fec02d4b77adbd2d60b0000000000000002000000000000000000000000000000000000000000000000000000000000000305746f6b656e166469726563745f7472616e736665725f7363726970740004202d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9100f636f6c6c656374696f6e5f6e616d650b0a746f6b656e5f6e616d65080100000000000000d0070000000000000100000000000000d20296490000000004020020b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a4920040334f8a9bba9897203732d87f6e835f1f7fdea0fcbfea5e90cee187395e6b5643c1e5c09b2f32c610200d5da46b3aefc7a69ac4fd06a2fb9172ca8c2785252303012d133ddd281bb6205558357cc6ac75661817e9aaeac3afebc32842759cbf7fa9010020aef3f4a4b8eca1dfc343361bf8e436bd42de9259c04b8314eb8e2054dd6e82ab40d4333493740ef2df40de4cd86fa51fc1f115e19cc806490be902323af6deb047936bdec7233dae2eeadd0618bceab7472875cbfa8b9ad0433eb145b0c2463606"

        self.verify_transactions(
            raw_transaction_input,
            raw_transaction_generated.inner(),
            signed_transaction_input,
            signed_transaction_generated,
        )

    def verify_transactions(
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

    def test_verify_fee_payer(self):
        # Generate fresh keys and create a working fee payer transaction
        sender_key = ed25519.PrivateKey.random()
        fee_payer_key = ed25519.PrivateKey.random()

        sender_addr = AccountAddress.from_key(sender_key.public_key())
        fee_payer_addr = AccountAddress.from_key(fee_payer_key.public_key())

        # Create a simple transaction
        payload = EntryFunction.natural(
            "0x1::supra_account",
            "transfer",
            [],
            [
                TransactionArgument(fee_payer_addr, Serializer.struct),
                TransactionArgument(100, Serializer.u64),
            ],
        )

        raw_txn = RawTransaction(
            sender_addr,
            1,
            TransactionPayload(payload),
            200000,
            100,
            1697670723,
            1,
        )

        # Create fee payer raw transaction
        fee_payer_raw_txn = FeePayerRawTransaction(raw_txn, [], fee_payer_addr)

        # Sign with both accounts
        sender_auth = fee_payer_raw_txn.sign(sender_key)
        fee_payer_auth = fee_payer_raw_txn.sign(fee_payer_key)

        # Create fee payer authenticator with correct structure
        authenticator = Authenticator(
            FeePayerAuthenticator(sender_auth, [], (fee_payer_addr, fee_payer_auth))
        )

        signed_txn = SignedTransaction(raw_txn, authenticator)

        # Generate the new corpus
        ser = Serializer()
        signed_txn.serialize(ser)
        print(f'signed_transaction_input = "{ser.output().hex()}"')

        # Verify it works
        self.assertTrue(
            isinstance(signed_txn.authenticator.authenticator, FeePayerAuthenticator)
        )
        self.assertTrue(signed_txn.verify())

    def test_verify_fee_payer(self):
        signed_transaction_input = "3d3891f51b2ecb09db9066313e0133e9a9f09b486277dedbd4697bdf6ab93e9401000000000000000200000000000000000000000000000000000000000000000000000000000000010d73757072615f6163636f756e74087472616e736665720002202a4ec963c67fe1301c5d6ab470c9460115f2de6ffb47477d5e706e8b8b726e2e086400000000000000400d030000000000640000000000000043663065000000000103002088e00cacc2797cdff594f235c17bad740d67dee0189fd93946a5f919593e8849402827444ca7ea75bb987d853c37c655422f792446b77537d01894eff235835702cdcc97897b0b225207feb74d338440ad8fb9338b0dfe31a8476c601d66fb770400002a4ec963c67fe1301c5d6ab470c9460115f2de6ffb47477d5e706e8b8b726e2e0020e2e231d9fe545bdf5b8e7a9aec21b3f8720c0e2e3cacfc4ea85eec50588a4446408ede4f45fcbc5e270a88d64aab744314ea1e4dc84b8ffa2c7ce7cdb9104f9bfaa92b67dabaf5c79887175beb43233a180baf5783c88e9baafb25b2acfb050908"
        der = Deserializer(bytes.fromhex(signed_transaction_input))
        signed_txn = der.struct(SignedTransaction)

        ser = Serializer()
        signed_txn.serialize(ser)
        self.assertEqual(ser.output().hex(), signed_transaction_input)

        self.assertTrue(
            isinstance(signed_txn.authenticator.authenticator, FeePayerAuthenticator)
        )
        self.assertTrue(signed_txn.verify())
