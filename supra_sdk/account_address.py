# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib

from supra_sdk import asymmetric_crypto, asymmetric_crypto_wrapper, ed25519
from supra_sdk.bcs import Deserializer, Serializer


class AuthKeyScheme:
    Ed25519: bytes = b"\x00"
    MultiEd25519: bytes = b"\x01"
    SingleKey: bytes = b"\x02"
    MultiKey: bytes = b"\x03"
    DeriveObjectAddressFromGuid: bytes = b"\xfd"
    DeriveObjectAddressFromSeed: bytes = b"\xfe"
    DeriveResourceAccountAddress: bytes = b"\xff"


class ParseAddressError(Exception):
    """There was an error parsing an address."""


class AccountAddress:
    address: bytes
    LENGTH: int = 32

    def __init__(self, address: bytes):
        self.address = address

        if len(address) != AccountAddress.LENGTH:
            raise ParseAddressError("Expected address of length 32")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAddress):
            return NotImplemented
        return self.address == other.address

    def __str__(self):
        """Represent an account address in a way that is compliant with the v1 address
        standard. The standard is defined as part of AIP-40, read more here:
        https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md

        In short, all special addresses SHOULD be represented in SHORT form, e.g.

        0x1

        All other addresses MUST be represented in LONG form, e.g.

        0x002098630cfad4734812fa37dc18d9b8d59242feabe49259e26318d468a99584

        For an explanation of what defines a "special" address, see `is_special`.

        All string representations of addresses MUST be prefixed with 0x.
        """
        suffix = self.address.hex()
        if self.is_special():
            suffix = suffix.lstrip("0") or "0"
        return f"0x{suffix}"

    def __repr__(self):
        return self.__str__()

    def is_special(self):
        """Returns whether the address is a "special" address. Addresses are considered
        special if the first 63 characters of the hex string are zero. In other words,
        an address is special if the first 31 bytes are zero and the last byte is
        smaller than `0b10000` (16). In other words, special is defined as an address
        that matches the following regex: `^0x0{63}[0-9a-f]$`. In short form this means
        the addresses in the range from `0x0` to `0xf` (inclusive) are special.

        For more details see the v1 address standard defined as part of AIP-40:
        https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md
        """
        return all(b == 0 for b in self.address[:-1]) and self.address[-1] < 0b10000

    @staticmethod
    def from_str(address: str) -> AccountAddress:
        """NOTE: This function has strict parsing behavior. For relaxed behavior, please use
        `from_string_relaxed` function.

        Creates an instance of AccountAddress from a hex string.

        This function allows only the strictest formats defined by AIP-40. In short this
        means only the following formats are accepted:
        - LONG
        - SHORT for special addresses

        Where:
        - LONG is defined as 0x + 64 hex characters.
        - SHORT for special addresses is 0x0 to 0xf inclusive without padding zeroes.

        This means the following are not accepted:
        - SHORT for non-special addresses.
        - Any address without a leading 0x.

        Learn more about the different address formats by reading AIP-40:
        https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md.

        Parameters
        ----------
        - address (str): A hex string representing an account address.

        Returns
        -------
        - AccountAddress: An instance of AccountAddress.

        """
        # Assert the string starts with 0x.
        if not address.startswith("0x"):
            raise RuntimeError("Hex string must start with a leading 0x.")

        out = AccountAddress.from_str_relaxed(address)

        # Check if the address is in LONG form. If it is not, this is only allowed for
        # special addresses, in which case we check it is in proper SHORT form.
        if len(address) != AccountAddress.LENGTH * 2 + 2:
            if not out.is_special():
                raise RuntimeError(
                    "The given hex string is not a special address, it must be represented "
                    "as 0x + 64 chars."
                )
            else:
                # 0x + one hex char is the only valid SHORT form for special addresses.
                if len(address) != 3:
                    raise RuntimeError(
                        "The given hex string is a special address not in LONG form, "
                        "it must be 0x0 to 0xf without padding zeroes."
                    )

        # Assert that only special addresses can use short form.
        if len(address[2:]) != AccountAddress.LENGTH * 2 and not out.is_special():
            raise RuntimeError(
                "Padding zeroes are not allowed, the address must be represented as "
                "0x0 to 0xf for special addresses or 0x + 64 chars for all other addresses."
            )

        return out

    @staticmethod
    def from_str_relaxed(address: str) -> AccountAddress:
        """NOTE: This function has relaxed parsing behavior. For strict behavior, please use
        the `from_string` function. Where possible, use `from_string` rather than this
        function. `from_string_relaxed` is only provided for backwards compatibility.

        Creates an instance of AccountAddress from a hex string.

        This function allows all formats defined by AIP-40. In short, this means the
        following formats are accepted:
        - LONG, with or without leading 0x
        - SHORT, with or without leading 0x

        Where:
        - LONG is 64 hex characters.
        - SHORT is 1 to 63 hex characters inclusive.
        - Padding zeroes are allowed, e.g., 0x0123 is valid.

        Learn more about the different address formats by reading AIP-40:
        https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md.

        Parameters
        ----------
        - address (str): A hex string representing an account address.

        Returns
        -------
        - AccountAddress: An instance of AccountAddress.

        """
        addr = address

        # Strip 0x prefix if present.
        if address[0:2] == "0x":
            addr = address[2:]

        # Assert the address is at least one hex char long.
        if len(addr) < 1:
            raise RuntimeError(
                "Hex string is too short, must be 1 to 64 chars long, excluding the "
                "leading 0x."
            )

        # Assert the address is at most 64 hex chars long.
        if len(addr) > 64:
            raise RuntimeError(
                "Hex string is too long, must be 1 to 64 chars long, excluding the "
                "leading 0x."
            )

        if len(addr) < AccountAddress.LENGTH * 2:
            pad = "0" * (AccountAddress.LENGTH * 2 - len(addr))
            addr = pad + addr

        return AccountAddress(bytes.fromhex(addr))

    @staticmethod
    def from_key(key: asymmetric_crypto.PublicKey) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(key.to_crypto_bytes())

        if isinstance(key, ed25519.PublicKey):
            hasher.update(AuthKeyScheme.Ed25519)
        elif isinstance(key, ed25519.MultiPublicKey):
            hasher.update(AuthKeyScheme.MultiEd25519)
        elif isinstance(key, asymmetric_crypto_wrapper.PublicKey):
            hasher.update(AuthKeyScheme.SingleKey)
        elif isinstance(key, asymmetric_crypto_wrapper.MultiPublicKey):
            hasher.update(AuthKeyScheme.MultiKey)
        else:
            raise Exception("Unsupported asymmetric_crypto.PublicKey key type.")

        return AccountAddress(hasher.digest())

    @staticmethod
    def for_resource_account(creator: AccountAddress, seed: bytes) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveResourceAccountAddress)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_guid_object(creator: AccountAddress, creation_num: int) -> AccountAddress:
        hasher = hashlib.sha3_256()
        serializer = Serializer()
        serializer.u64(creation_num)
        hasher.update(serializer.output())
        hasher.update(creator.address)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromGuid)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_object(creator: AccountAddress, seed: bytes) -> AccountAddress:
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromSeed)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_token(
        creator: AccountAddress, collection_name: str, token_name: str
    ) -> AccountAddress:
        collection_bytes = collection_name.encode()
        token_bytes = token_name.encode()
        return AccountAddress.for_named_object(
            creator, collection_bytes + b"::" + token_bytes
        )

    @staticmethod
    def for_named_collection(
        creator: AccountAddress, collection_name: str
    ) -> AccountAddress:
        return AccountAddress.for_named_object(creator, collection_name.encode())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAddress:
        return AccountAddress(deserializer.fixed_bytes(AccountAddress.LENGTH))

    def serialize(self, serializer: Serializer):
        serializer.fixed_bytes(self.address)
