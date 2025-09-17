# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast

from nacl.signing import SigningKey, VerifyKey

from supra_sdk import asymmetric_crypto
from supra_sdk.bcs import Deserializer, Serializer


class PrivateKey(asymmetric_crypto.PrivateKey):
    LENGTH: int = 32

    key: SigningKey

    def __init__(self, key: SigningKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self):
        return self.hex()

    @staticmethod
    def from_str(value: str) -> PrivateKey:
        if value[0:2] == "0x":
            value = value[2:]
        return PrivateKey(SigningKey(bytes.fromhex(value)))

    def hex(self) -> str:
        return f"0x{self.key.encode().hex()}"

    def public_key(self) -> PublicKey:
        return PublicKey(self.key.verify_key)

    @staticmethod
    def random() -> PrivateKey:
        return PrivateKey(SigningKey.generate())

    def sign(self, data: bytes) -> Signature:
        return Signature(self.key.sign(data).signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        key = deserializer.to_bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")

        return PrivateKey(SigningKey(key))

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.key.encode())


class PublicKey(asymmetric_crypto.PublicKey):
    LENGTH: int = 32

    key: VerifyKey

    def __init__(self, key: VerifyKey):
        self.key = key

    def __eq__(self, other: object):
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self) -> str:
        return f"0x{self.key.encode().hex()}"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signature = cast(Signature, signature)
            self.key.verify(data, signature.data())
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        return self.key.encode()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        key = deserializer.to_bytes()
        if len(key) != PublicKey.LENGTH:
            raise Exception("Length mismatch")

        return PublicKey(VerifyKey(key))

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.key.encode())


class MultiPublicKey(asymmetric_crypto.PublicKey):
    keys: list[PublicKey]
    threshold: int

    MIN_KEYS = 2
    MAX_KEYS = 32
    MIN_THRESHOLD = 1

    def __init__(self, keys: list[PublicKey], threshold: int):
        assert self.MIN_KEYS <= len(keys) <= self.MAX_KEYS, (
            f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} keys."
        )
        assert self.MIN_THRESHOLD <= threshold <= len(keys), (
            f"Threshold must be between {self.MIN_THRESHOLD} and {len(keys)}."
        )

        self.keys = keys
        self.threshold = threshold

    def __str__(self) -> str:
        return f"{self.threshold}-of-{len(self.keys)} Multi-Ed25519 public key"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signatures = cast(MultiSignature, signature)
            assert self.threshold <= len(signatures.signatures), (
                f"Insufficient signatures, {self.threshold} > {len(signatures.signatures)}"
            )

            for idx, signature in signatures.signatures:
                assert len(self.keys) > idx, (
                    f"Signature index exceeds available keys {len(self.keys)} < {idx}"
                )
                assert self.keys[idx].verify(data, signature), (
                    "Unable to verify signature"
                )
        except Exception:
            return False
        return True

    @staticmethod
    def from_crypto_bytes(indata: bytes) -> MultiPublicKey:
        total_keys = int(len(indata) / PublicKey.LENGTH)
        keys: list[PublicKey] = []
        for idx in range(total_keys):
            start = idx * PublicKey.LENGTH
            end = (idx + 1) * PublicKey.LENGTH
            keys.append(PublicKey(VerifyKey(indata[start:end])))
        threshold = indata[-1]
        return MultiPublicKey(keys, threshold)

    def to_crypto_bytes(self) -> bytes:
        key_bytes = bytearray()
        for key in self.keys:
            key_bytes.extend(key.to_crypto_bytes())
        key_bytes.append(self.threshold)
        return key_bytes

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiPublicKey:
        indata = deserializer.to_bytes()
        return MultiPublicKey.from_crypto_bytes(indata)

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.to_crypto_bytes())


class Signature(asymmetric_crypto.Signature):
    LENGTH: int = 64

    signature: bytes

    def __init__(self, signature: bytes):
        self.signature = signature

    def __eq__(self, other: object):
        if not isinstance(other, Signature):
            return NotImplemented
        return self.signature == other.signature

    def __str__(self) -> str:
        return f"0x{self.signature.hex()}"

    @staticmethod
    def get_null_signature() -> Signature:
        return Signature(bytes(Signature.LENGTH))

    def data(self) -> bytes:
        return self.signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        signature = deserializer.to_bytes()
        if len(signature) != Signature.LENGTH:
            raise Exception("Length mismatch")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.signature)


class MultiSignature(asymmetric_crypto.Signature):
    signatures: list[tuple[int, Signature]]
    BITMAP_NUM_OF_BYTES: int = 4

    def __init__(self, signatures: list[tuple[int, Signature]]):
        for signature in signatures:
            assert signature[0] < self.BITMAP_NUM_OF_BYTES * 8, (
                "bitmap value exceeds maximum value"
            )
        self.signatures = signatures

    def __eq__(self, other: object):
        if not isinstance(other, MultiSignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        return f"{self.signatures}"

    @staticmethod
    def from_key_map(
        public_key: MultiPublicKey,
        signatures_map: list[tuple[PublicKey, Signature]],
    ) -> MultiSignature:
        signatures = []

        for entry in signatures_map:
            signatures.append((public_key.keys.index(entry[0]), entry[1]))
        return MultiSignature(signatures)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiSignature:
        signature_bytes = deserializer.to_bytes()
        count = len(signature_bytes) // Signature.LENGTH
        assert count * Signature.LENGTH + MultiSignature.BITMAP_NUM_OF_BYTES == len(
            signature_bytes
        ), "MultiSignature length is invalid"

        bitmap = int.from_bytes(signature_bytes[-4:], "big")

        current = 0
        position = 0
        signatures = []
        while current < count:
            to_check = 1 << (31 - position)
            if to_check & bitmap:
                left = current * Signature.LENGTH
                signature = Signature(signature_bytes[left : left + Signature.LENGTH])
                signatures.append((position, signature))
                current += 1
            position += 1

        return MultiSignature(signatures)

    def serialize(self, serializer: Serializer):
        signature_bytes = bytearray()
        bitmap = 0

        for signature in self.signatures:
            shift = 31 - signature[0]
            bitmap = bitmap | (1 << shift)
            signature_bytes.extend(signature[1].data())

        signature_bytes.extend(
            bitmap.to_bytes(MultiSignature.BITMAP_NUM_OF_BYTES, "big")
        )
        serializer.to_bytes(signature_bytes)

    def unset_signatures(self):
        null_signature = Signature.get_null_signature()
        for i, (pubkey_index, _signature) in enumerate(self.signatures):
            self.signatures[i] = (pubkey_index, null_signature)
