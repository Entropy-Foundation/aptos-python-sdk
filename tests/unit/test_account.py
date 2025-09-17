# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest

from supra_sdk.account import Account, RotationProofChallenge
from supra_sdk.bcs import Serializer


class Test(unittest.TestCase):
    def test_load_and_store(self):
        (_file, path) = tempfile.mkstemp()
        start = Account.generate()
        start.store(path)
        load = Account.load(path)

        self.assertEqual(start, load)
        # Auth key and Account address should be the same at start
        self.assertEqual(str(start.address()), start.auth_key())

    def test_key(self):
        message = b"test message"
        account = Account.generate()
        signature = account.sign(message)
        self.assertTrue(account.public_key().verify(message, signature))

    def test_rotation_proof_challenge(self):
        # Create originating account from private key.
        originating_account = Account.load_key(
            "005120c5882b0d492b3d2dc60a8a4510ec2051825413878453137305ba2d644b"
        )
        # Create target account from private key.
        target_account = Account.load_key(
            "19d409c191b1787d5b832d780316b83f6ee219677fafbd4c0f69fee12fdcdcee"
        )
        # Construct rotation proof challenge.
        rotation_proof_challenge = RotationProofChallenge(
            sequence_number=1234,
            originator=originating_account.address(),
            current_auth_key=originating_account.address(),
            new_public_key=target_account.public_key(),
        )
        # Serialize transaction.
        serializer = Serializer()
        rotation_proof_challenge.serialize(serializer)
        rotation_proof_challenge_bcs = serializer.output().hex()
        # Compare against expected bytes.
        expected_bytes = (
            "0000000000000000000000000000000000000000000000000000000000000001"
            "076163636f756e7416526f746174696f6e50726f6f664368616c6c656e6765d2"
            "0400000000000015b67a673979c7c5dfc8d9c9f94d02da35062a19dd9d218087"
            "bd9076589219c615b67a673979c7c5dfc8d9c9f94d02da35062a19dd9d218087"
            "bd9076589219c620a1f942a3c46e2a4cd9552c0f95d529f8e3b60bcd44408637"
            "9ace35e4458b9f22"
        )
        self.assertEqual(rotation_proof_challenge_bcs, expected_bytes)
