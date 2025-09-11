# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from dataclasses import dataclass

from supra_sdk import ed25519
from supra_sdk.account_address import AccountAddress


@dataclass(init=True, frozen=True)
class TestAddresses:
    short_with_0x: str
    short_without_0x: str
    long_with_0x: str
    long_without_0x: str
    bytes: bytes


ADDRESS_ZERO = TestAddresses(
    short_with_0x="0x0",
    short_without_0x="0",
    long_with_0x="0x0000000000000000000000000000000000000000000000000000000000000000",
    long_without_0x="0000000000000000000000000000000000000000000000000000000000000000",
    bytes=bytes([0] * 32),
)

ADDRESS_F = TestAddresses(
    short_with_0x="0xf",
    short_without_0x="f",
    long_with_0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    long_without_0x="000000000000000000000000000000000000000000000000000000000000000f",
    bytes=bytes([0] * 31 + [15]),
)

ADDRESS_F_PADDED_SHORT_FORM = TestAddresses(
    short_with_0x="0x0f",
    short_without_0x="0f",
    # The rest of these below are the same as for ADDRESS_F.
    long_with_0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    long_without_0x="000000000000000000000000000000000000000000000000000000000000000f",
    bytes=bytes([0] * 31 + [15]),
)

ADDRESS_TEN = TestAddresses(
    short_with_0x="0x10",
    short_without_0x="10",
    long_with_0x="0x0000000000000000000000000000000000000000000000000000000000000010",
    long_without_0x="0000000000000000000000000000000000000000000000000000000000000010",
    bytes=bytes([0] * 31 + [16]),
)

ADDRESS_OTHER = TestAddresses(
    short_with_0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    short_without_0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    long_with_0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    long_without_0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    bytes=bytes(
        [
            202,
            132,
            50,
            121,
            227,
            66,
            113,
            68,
            206,
            173,
            94,
            77,
            89,
            153,
            163,
            208,
            202,
            132,
            50,
            121,
            227,
            66,
            113,
            68,
            206,
            173,
            94,
            77,
            89,
            153,
            163,
            208,
        ]
    ),
)


class Test(unittest.TestCase):
    def test_multi_ed25519(self):
        private_key_1 = ed25519.PrivateKey.from_str(
            "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = ed25519.PrivateKey.from_str(
            "1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        multisig_public_key = ed25519.MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )

        expected = AccountAddress.from_str_relaxed(
            "835bb8c5ee481062946b18bbb3b42a40b998d6bf5316ca63834c959dc739acf0"
        )
        actual = AccountAddress.from_key(multisig_public_key)
        self.assertEqual(actual, expected)

    def test_resource_account(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "ee89f8c763c27f9d942d496c1a0dcf32d5eacfe78416f9486b8db66155b163b0"
        )
        actual = AccountAddress.for_resource_account(base_address, b"\x0b\x00\x0b")
        self.assertEqual(actual, expected)

    def test_named_object(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_object(base_address, b"bob's collection")
        self.assertEqual(actual, expected)

    def test_collection(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_collection(base_address, "bob's collection")
        self.assertEqual(actual, expected)

    def test_token(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "e20d1f22a5400ba7be0f515b7cbd00edc42dbcc31acc01e31128b2b5ddb3c56e"
        )
        actual = AccountAddress.for_named_token(
            base_address, "bob's collection", "bob's token"
        )
        self.assertEqual(actual, expected)

    def test_to_standard_string(self):
        # Test special address: 0x0
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                )
            ),
            "0x0",
        )

        # Test special address: 0x1
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                )
            ),
            "0x1",
        )

        # Test special address: 0x4
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000004"
                )
            ),
            "0x4",
        )

        # Test special address: 0xf
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x000000000000000000000000000000000000000000000000000000000000000f"
                )
            ),
            "0xf",
        )

        # Test special address from short no 0x: d
        self.assertEqual(
            str(AccountAddress.from_str_relaxed("d")),
            "0xd",
        )

        # Test non-special address from long:
        # 0x0000000000000000000000000000000000000000000000000000000000000010
        value = "0x0000000000000000000000000000000000000000000000000000000000000010"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long:
        # 0x000000000000000000000000000000000000000000000000000000000000001f
        value = "0x000000000000000000000000000000000000000000000000000000000000001f"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long:
        # 0x00000000000000000000000000000000000000000000000000000000000000a0
        value = "0x00000000000000000000000000000000000000000000000000000000000000a0"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long no 0x:
        # ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0
        value = "ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

        # Test non-special address from long no 0x:
        # 1000000000000000000000000000000000000000000000000000000000000000
        value = "1000000000000000000000000000000000000000000000000000000000000000"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

        # Demonstrate that neither leading nor trailing zeroes get trimmed for
        # non-special addresses:
        # 0f00000000000000000000000000000000000000000000000000000000000000
        value = "0f00000000000000000000000000000000000000000000000000000000000000"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

    def test_from_str_relaxed(self):
        # Demonstrate that all formats are accepted for 0x0.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.long_with_0x)),
            ADDRESS_ZERO.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.long_without_0x)),
            ADDRESS_ZERO.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.short_with_0x)),
            ADDRESS_ZERO.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.short_without_0x)),
            ADDRESS_ZERO.short_with_0x,
        )

        # Demonstrate that all formats are accepted for 0xf.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.long_with_0x)),
            ADDRESS_F.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.long_without_0x)),
            ADDRESS_F.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.short_with_0x)),
            ADDRESS_F.short_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.short_without_0x)),
            ADDRESS_F.short_with_0x,
        )

        # Demonstrate that padding zeroes are allowed for 0x0f.
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    ADDRESS_F_PADDED_SHORT_FORM.short_with_0x
                )
            ),
            ADDRESS_F.short_with_0x,
        )
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    ADDRESS_F_PADDED_SHORT_FORM.short_without_0x
                )
            ),
            ADDRESS_F.short_with_0x,
        )

        # Demonstrate that all formats are accepted for 0x10.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.long_with_0x)),
            ADDRESS_TEN.long_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.long_without_0x)),
            ADDRESS_TEN.long_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.short_with_0x)),
            ADDRESS_TEN.long_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.short_without_0x)),
            ADDRESS_TEN.long_with_0x,
        )

        # Demonstrate that all formats are accepted for other addresses.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_OTHER.long_with_0x)),
            ADDRESS_OTHER.long_with_0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_OTHER.long_without_0x)),
            ADDRESS_OTHER.long_with_0x,
        )

    def test_from_str(self):
        # Demonstrate that only LONG and SHORT are accepted for 0x0.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_ZERO.long_with_0x)),
            ADDRESS_ZERO.short_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_ZERO.long_without_0x
        )
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_ZERO.short_with_0x)),
            ADDRESS_ZERO.short_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_ZERO.short_without_0x
        )

        # Demonstrate that only LONG and SHORT are accepted for 0xf.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_F.long_with_0x)),
            ADDRESS_F.short_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_F.long_without_0x
        )
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_F.short_with_0x)),
            ADDRESS_F.short_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_F.short_without_0x
        )

        # Demonstrate that padding zeroes are not allowed for 0x0f.
        self.assertRaises(
            RuntimeError,
            AccountAddress.from_str,
            ADDRESS_F_PADDED_SHORT_FORM.short_with_0x,
        )
        self.assertRaises(
            RuntimeError,
            AccountAddress.from_str,
            ADDRESS_F_PADDED_SHORT_FORM.short_without_0x,
        )

        # Demonstrate that only LONG format is accepted for 0x10.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_TEN.long_with_0x)),
            ADDRESS_TEN.long_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.long_without_0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.short_with_0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.short_without_0x
        )

        # Demonstrate that only LONG format is accepted for other addresses.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_OTHER.long_with_0x)),
            ADDRESS_OTHER.long_with_0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_OTHER.long_without_0x
        )
