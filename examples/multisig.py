# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import subprocess
import sys
import time
from typing import cast

from examples.common import FAUCET_URL, NODE_URL, SUPRA_CORE_PATH
from supra_sdk import ed25519
from supra_sdk.account import Account, RotationProofChallenge
from supra_sdk.account_address import AccountAddress
from supra_sdk.async_client import FaucetClient, RestClient
from supra_sdk.authenticator import Authenticator, MultiEd25519Authenticator
from supra_sdk.bcs import Serializer
from supra_sdk.ed25519 import MultiPublicKey, MultiSignature
from supra_sdk.transactions import (
    EntryFunction,
    RawTransaction,
    Script,
    ScriptArgument,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag

should_wait = True


def wait():
    """Wait for user to press Enter before starting next section."""
    if should_wait:
        input("\nPress Enter to continue...")


async def main(should_wait_input: bool):
    global should_wait
    should_wait = should_wait_input

    rest_client = RestClient(NODE_URL)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    alice = Account.generate()
    bob = Account.generate()
    chad = Account.generate()

    print("\n=== Account addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob:   {bob.address()}")
    print(f"Chad:  {chad.address()}")

    print("\n=== Authentication keys ===")
    print(f"Alice: {alice.auth_key()}")
    print(f"Bob:   {bob.auth_key()}")
    print(f"Chad:  {chad.auth_key()}")

    print("\n=== Public keys ===")
    print(f"Alice: {alice.public_key()}")
    print(f"Bob:   {bob.public_key()}")
    print(f"Chad:  {chad.public_key()}")
    wait()

    threshold = 2
    multisig_public_key = MultiPublicKey(
        [
            cast(ed25519.PublicKey, alice.public_key()),
            cast(ed25519.PublicKey, bob.public_key()),
            cast(ed25519.PublicKey, chad.public_key()),
        ],
        threshold,
    )
    multisig_address = AccountAddress.from_key(multisig_public_key)
    print("\n=== 2-of-3 Multisig account ===")
    print(f"Account public key: {multisig_public_key}")
    print(f"Account address:    {multisig_address}")
    wait()

    print("\n=== Funding accounts ===")
    await faucet_client.faucet(alice.address())
    await faucet_client.faucet(bob.address())
    await faucet_client.faucet(chad.address())
    await faucet_client.faucet(multisig_address)

    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    chad_balance = await rest_client.account_supra_balance(chad.address())
    multisig_balance = await rest_client.account_supra_balance(multisig_address)

    print(f"Alice's balance:  {alice_balance}")
    print(f"Bob's balance:    {bob_balance}")
    print(f"Chad's balance:   {chad_balance}")
    print(f"Multisig balance: {multisig_balance}")
    wait()

    entry_function = EntryFunction.natural(
        module="0x1::coin",
        function="transfer",
        ty_args=[TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
        args=[
            TransactionArgument(chad.address(), Serializer.struct),
            TransactionArgument(100, Serializer.u64),
        ],
    )

    chain_id = await rest_client.chain_id()
    raw_transaction = RawTransaction(
        sender=multisig_address,
        sequence_number=0,
        payload=TransactionPayload(entry_function),
        max_gas_amount=rest_client.client_config.max_gas_amount,
        gas_unit_price=rest_client.client_config.gas_unit_price,
        expiration_timestamps_secs=(
            int(time.time()) + rest_client.client_config.expiration_ttl
        ),
        chain_id=chain_id,
    )

    alice_signature = cast(ed25519.Signature, alice.sign(raw_transaction.keyed()))
    bob_signature = cast(ed25519.Signature, bob.sign(raw_transaction.keyed()))

    assert raw_transaction.verify(
        cast(ed25519.PublicKey, alice.public_key()),
        alice_signature,
    )
    assert raw_transaction.verify(
        cast(ed25519.PublicKey, bob.public_key()),
        bob_signature,
    )

    print("\n=== Individual signatures ===")
    print(f"Alice: {alice_signature}")
    print(f"Bob:   {bob_signature}")
    wait()

    # Map from signatory public key index to signature.
    sig_map = [(0, alice_signature), (1, bob_signature)]
    multisig_signature = MultiSignature(sig_map)
    authenticator = Authenticator(
        MultiEd25519Authenticator(multisig_public_key, multisig_signature)
    )
    signed_transaction = SignedTransaction(raw_transaction, authenticator)
    print("\n=== Submitting transfer transaction ===")

    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"Transaction hash: {tx_hash}")
    wait()

    print("\n=== New account balances===")
    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    chad_balance = await rest_client.account_supra_balance(chad.address())
    multisig_balance = await rest_client.account_supra_balance(multisig_address)
    print(f"Alice's balance:  {alice_balance}")
    print(f"Bob's balance:    {bob_balance}")
    print(f"Chad's balance:   {chad_balance}")
    print(f"Multisig balance: {multisig_balance}")
    wait()

    print("\n=== Funding vanity address ===")
    deedee = Account.generate()
    while str(deedee.address())[2:4] != "dd":
        deedee = Account.generate()
    print(f"Deedee's address:    {deedee.address()}")
    print(f"Deedee's public key: {deedee.public_key()}")

    await faucet_client.faucet(deedee.address())
    deedee_balance = await rest_client.account_supra_balance(deedee.address())
    print(f"Deedee's balance:    {deedee_balance}")  # <:!:section_7
    wait()

    print("\n=== Signing rotation proof challenge ===")
    rotation_proof_challenge = RotationProofChallenge(
        sequence_number=0,
        originator=deedee.address(),
        current_auth_key=deedee.address(),
        new_public_key=multisig_public_key,
    )
    serializer = Serializer()
    rotation_proof_challenge.serialize(serializer)
    rotation_proof_challenge_bcs = serializer.output()
    cap_rotate_key = deedee.sign(rotation_proof_challenge_bcs)
    cap_update_table = MultiSignature(
        [
            (1, cast(ed25519.Signature, bob.sign(rotation_proof_challenge_bcs))),
            (2, cast(ed25519.Signature, chad.sign(rotation_proof_challenge_bcs))),
        ],
    )
    print(f"cap_rotate_key:   0x{cap_rotate_key.to_bytes().hex()}")
    print(f"cap_update_table: 0x{cap_update_table.to_bytes().hex()}")
    wait()

    print("\n=== Submitting authentication key rotation transaction ===")
    entry_function = EntryFunction.natural(
        module="0x1::account",
        function="rotate_authentication_key",
        ty_args=[],
        args=[
            TransactionArgument(Authenticator.ED25519, Serializer.u8),
            TransactionArgument(deedee.public_key(), Serializer.struct),
            TransactionArgument(Authenticator.MULTI_ED25519, Serializer.u8),
            TransactionArgument(multisig_public_key, Serializer.struct),
            TransactionArgument(cap_rotate_key, Serializer.struct),
            TransactionArgument(cap_update_table, Serializer.struct),
        ],
    )
    signed_transaction = await rest_client.create_signed_transaction(
        deedee, TransactionPayload(entry_function)
    )
    account_data = await rest_client.account(deedee.address())
    print(f"Auth key pre-rotation: {account_data['authentication_key']}")

    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"Transaction hash:      {tx_hash}")

    account_data = await rest_client.account(deedee.address())
    print(f"New auth key:          {account_data['authentication_key']}")
    print(f"1st multisig address:  {multisig_address}")  # <:!:section_9
    wait()

    print("\n=== Genesis publication ===")
    packages_dir = f"{SUPRA_CORE_PATH}/aptos-move/move-examples/upgrade_and_govern/"

    command = (
        f"supra move tool compile "
        f"--save-metadata "
        f"--package-dir {packages_dir}genesis "
        f"--named-addresses upgrade_and_govern={str(deedee.address())}"
    )

    print(f"Running supra CLI command: {command}\n")
    subprocess.run(command.split(), stdout=subprocess.PIPE)

    build_path = f"{packages_dir}genesis/build/UpgradeAndGovern/"

    with open(f"{build_path}package-metadata.bcs", "rb") as f:
        package_metadata = f.read()

    with open(f"{build_path}bytecode_modules/parameters.mv", "rb") as f:
        parameters_module = f.read()

    modules_serializer = Serializer.sequence_serializer(Serializer.to_bytes)

    payload = EntryFunction.natural(
        module="0x1::code",
        function="publish_package_txn",
        ty_args=[],
        args=[
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument([parameters_module], modules_serializer),
        ],
    )

    raw_transaction = RawTransaction(
        sender=deedee.address(),
        sequence_number=1,
        payload=TransactionPayload(payload),
        max_gas_amount=rest_client.client_config.max_gas_amount,
        gas_unit_price=rest_client.client_config.gas_unit_price,
        expiration_timestamps_secs=(
            int(time.time()) + rest_client.client_config.expiration_ttl
        ),
        chain_id=chain_id,
    )

    alice_signature = cast(ed25519.Signature, alice.sign(raw_transaction.keyed()))
    chad_signature = cast(ed25519.Signature, chad.sign(raw_transaction.keyed()))
    # Map from signatory public key to signature.
    sig_map = [(0, alice_signature), (2, chad_signature)]
    multisig_signature = MultiSignature(sig_map)
    authenticator = Authenticator(
        MultiEd25519Authenticator(multisig_public_key, multisig_signature)
    )

    signed_transaction = SignedTransaction(raw_transaction, authenticator)
    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"\nTransaction hash: {tx_hash}")

    registry = await rest_client.account_resource(
        deedee.address(), "0x1::code::PackageRegistry"
    )
    package_name = registry["data"]["packages"][0]["name"]
    n_upgrades = registry["data"]["packages"][0]["upgrade_number"]
    print(f"Package name from on-chain registry: {package_name}")
    print(f"On-chain upgrade number: {n_upgrades}")  # <:!:section_10
    wait()

    print("\n=== Upgrade publication ===")
    command = (
        f"supra move tool compile "
        f"--save-metadata "
        f"--package-dir {packages_dir}upgrade "
        f"--named-addresses upgrade_and_govern={str(deedee.address())}"
    )

    print(f"Running supra CLI command: {command}\n")
    subprocess.run(command.split(), stdout=subprocess.PIPE)
    build_path = f"{packages_dir}upgrade/build/UpgradeAndGovern/"

    with open(f"{build_path}package-metadata.bcs", "rb") as f:
        package_metadata = f.read()

    with open(f"{build_path}bytecode_modules/parameters.mv", "rb") as f:
        parameters_module = f.read()

    with open(f"{build_path}bytecode_modules/transfer.mv", "rb") as f:
        transfer_module = f.read()

    entry_function_payload = EntryFunction.natural(
        module="0x1::code",
        function="publish_package_txn",
        ty_args=[],
        args=[
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument(  # Transfer module listed second.
                [parameters_module, transfer_module],
                Serializer.sequence_serializer(Serializer.to_bytes),
            ),
        ],
    )

    raw_transaction = RawTransaction(
        sender=deedee.address(),
        sequence_number=2,
        payload=TransactionPayload(entry_function_payload),
        max_gas_amount=rest_client.client_config.max_gas_amount,
        gas_unit_price=rest_client.client_config.gas_unit_price,
        expiration_timestamps_secs=(
            int(time.time()) + rest_client.client_config.expiration_ttl
        ),
        chain_id=chain_id,
    )

    alice_signature = cast(ed25519.Signature, alice.sign(raw_transaction.keyed()))
    bob_signature = cast(ed25519.Signature, bob.sign(raw_transaction.keyed()))
    chad_signature = cast(ed25519.Signature, chad.sign(raw_transaction.keyed()))

    # Map from signatory public key to signature.
    sig_map = [(0, alice_signature), (1, bob_signature), (2, chad_signature)]
    multisig_signature = MultiSignature(sig_map)

    authenticator = Authenticator(
        MultiEd25519Authenticator(multisig_public_key, multisig_signature)
    )

    signed_transaction = SignedTransaction(raw_transaction, authenticator)
    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"\nTransaction hash: {tx_hash}")

    registry = await rest_client.account_resource(
        deedee.address(), "0x1::code::PackageRegistry"
    )
    n_upgrades = registry["data"]["packages"][0]["upgrade_number"]
    print(f"On-chain upgrade number: {n_upgrades}")
    wait()

    print("\n=== Invoking Move script ===")
    with open(f"{build_path}bytecode_scripts/set_and_transfer.mv", "rb") as f:
        script_code = f.read()
    script_payload = Script(
        code=script_code,
        ty_args=[],
        args=[
            ScriptArgument(ScriptArgument.ADDRESS, alice.address()),
            ScriptArgument(ScriptArgument.ADDRESS, bob.address()),
        ],
    )
    raw_transaction = RawTransaction(
        sender=deedee.address(),
        sequence_number=3,
        payload=TransactionPayload(script_payload),
        max_gas_amount=rest_client.client_config.max_gas_amount,
        gas_unit_price=rest_client.client_config.gas_unit_price,
        expiration_timestamps_secs=(
            int(time.time()) + rest_client.client_config.expiration_ttl
        ),
        chain_id=chain_id,
    )

    alice_signature = cast(ed25519.Signature, alice.sign(raw_transaction.keyed()))
    bob_signature = cast(ed25519.Signature, bob.sign(raw_transaction.keyed()))

    # Map from signatory public key index to signature.
    sig_map = [(0, alice_signature), (1, bob_signature)]
    multisig_signature = MultiSignature(sig_map)

    authenticator = Authenticator(
        MultiEd25519Authenticator(multisig_public_key, multisig_signature)
    )

    signed_transaction = SignedTransaction(raw_transaction, authenticator)
    tx_hash = await rest_client.submit_transaction(signed_transaction)
    print(f"Transaction hash: {tx_hash}")

    alice_balance = await rest_client.account_supra_balance(alice.address())
    bob_balance = await rest_client.account_supra_balance(bob.address())
    chad_balance = await rest_client.account_supra_balance(chad.address())
    multisig_balance = await rest_client.account_supra_balance(multisig_address)
    print(f"Alice's balance:  {alice_balance}")
    print(f"Bob's balance:    {bob_balance}")
    print(f"Chad's balance:   {chad_balance}")
    print(f"Multisig balance: {multisig_balance}")


if __name__ == "__main__":
    asyncio.run(
        main(sys.argv[1].lower() in ("true", "1") if len(sys.argv) == 2 else False)
    )
