# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest

from supra_sdk.bcs import Deserializer, Serializer
from supra_sdk.ed25519 import (
    MultiPublicKey,
    MultiSignature,
    PrivateKey,
    PublicKey,
    Signature,
)


class Test(unittest.TestCase):
    def test_sign_and_verify(self):
        in_value = b"test_message"

        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        signature = private_key.sign(in_value)
        self.assertTrue(public_key.verify(in_value, signature))

    def test_private_key_serialization(self):
        private_key = PrivateKey.random()
        ser = Serializer()

        private_key.serialize(ser)
        ser_private_key = PrivateKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(private_key, ser_private_key)

    def test_public_key_serialization(self):
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        ser = Serializer()
        public_key.serialize(ser)
        ser_public_key = PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(public_key, ser_public_key)

    def test_signature_key_serialization(self):
        private_key = PrivateKey.random()
        in_value = b"another_message"
        signature = private_key.sign(in_value)

        ser = Serializer()
        signature.serialize(ser)
        ser_signature = Signature.deserialize(Deserializer(ser.output()))
        self.assertEqual(signature, ser_signature)

    def test_multisig(self):
        # Generate signatory private keys.
        private_key_1 = PrivateKey.from_str(
            "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = PrivateKey.from_str(
            "1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        # Generate multisig public key with threshold of 1.
        multisig_public_key = MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_public_key_bcs = (
            "41754bb6a4720a658bdd5f532995955db0971ad3519acbde2f1149c3857348006c"
            "1634cd4607073f2be4a6f2aadc2b866ddb117398a675f2096ed906b20e0bf2c901"
        )
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Get public key bytes representation.
        public_key_bytes = multisig_public_key.to_bytes()
        # Convert back to multisig class instance from bytes.
        multisig_public_key = MultiPublicKey.from_bytes(public_key_bytes)
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Assert BCS representation is the same.
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Have one signer sign arbitrary message.
        signature = private_key_2.sign(b"multisig")
        # Compose multisig signature.
        multisig_signature = MultiSignature.from_key_map(
            multisig_public_key, [(private_key_2.public_key(), signature)]
        )
        # Get signature BCS representation.
        serializer = Serializer()
        multisig_signature.serialize(serializer)
        multisig_signature_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_multisig_signature_bcs = (
            "4402e90d8f300d79963cb7159ffa6f620f5bba4af5d32a7176bfb5480b43897cf"
            "4886bbb4042182f4647c9b04f02dbf989966f0facceec52d22bdcc7ce631bfc0c"
            "40000000"
        )
        self.assertEqual(multisig_signature_bcs, expected_multisig_signature_bcs)
        deserializer = Deserializer(bytes.fromhex(expected_multisig_signature_bcs))
        multisig_signature_deserialized = deserializer.struct(MultiSignature)
        self.assertEqual(multisig_signature_deserialized, multisig_signature)

        self.assertTrue(multisig_public_key.verify(b"multisig", multisig_signature))

        multisig_signature.unset_signatures()
        null_signature = Signature.get_null_signature()
        for signature in multisig_signature.signatures:
            self.assertEqual(signature[1], null_signature)

    def test_multisig_range_checks(self):
        # Generate public keys.
        keys = [
            PrivateKey.random().public_key() for x in range(MultiPublicKey.MAX_KEYS + 1)
        ]
        # Verify failure for initializing multisig instance with too few keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey([keys[0]], 1)
        # Verify failure for initializing multisig instance with too many keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey(keys, 1)
        # Verify failure for initializing multisig instance with small threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey(keys[0:4], 0)
        # Verify failure for initializing multisig instance with large threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey(keys[0:4], 5)
        # Verify failure for initializing from bytes with too few keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey([keys[0]], 1).to_bytes())
        # Verify failure for initializing from bytes with too many keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey(keys, 1).to_bytes())
        # Verify failure for initializing from bytes with small threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 0).to_bytes())
        # Verify failure for initializing from bytes with large threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 5).to_bytes())
