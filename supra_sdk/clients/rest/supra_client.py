# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import asyncio
import copy
import time
from dataclasses import dataclass
from typing import Any

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.authenticator import (
    Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
)
from supra_sdk.bcs import Serializer
from supra_sdk.clients import ApiClient, ApiClientConfig
from supra_sdk.clients.rest.account import AccountRestClient
from supra_sdk.clients.rest.block import BlockRestClient
from supra_sdk.clients.rest.consensus import ConsensusRestClient
from supra_sdk.clients.rest.faucet import FaucetRestClient
from supra_sdk.clients.rest.general import GeneralRestClient
from supra_sdk.clients.rest.transaction import TransactionRestClient
from supra_sdk.transactions import (
    AutomationRegistrationParams,
    AutomationRegistrationParamsV1,
    EntryFunction,
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    SupraTransaction,
    TransactionArgument,
    TransactionPayload,
)
from supra_sdk.type_tag import StructTag, TypeTag


@dataclass
class TransactionConfig:
    """Configuration options for transaction payload generation and polling.

    This dataclass defines default parameters that are used in transaction payload generation and polling operation.
    It is intended to be passed into functions of the `SupraClient` that involves transaction payload generation and
    submission.

    Attributes:
        expiration_ttl (int): Time-to-live, in seconds, before a transaction expires and is rejected by the network.
            Defaults to 600.
        gas_unit_price (int): Price per unit of gas used to execute the transaction. Defaults to 100.
        max_gas_amount (int): Maximum number of gas units allowed per transaction. Defaults to 500,000.
        transaction_wait_time_in_seconds (int): Number of seconds to wait for a transaction to be executed before timing
            out. Defaults to 20.
        polling_wait_time_in_seconds (int): Delay, in seconds, between successive polling attempts when waiting for
        transaction confirmation. Defaults to 1.
        wait_for_transaction (bool): Whether to wait for the transaction to be confirmed after submission.
            Defaults to True.

    """

    expiration_ttl: int = 600
    gas_unit_price: int = 100
    max_gas_amount: int = 500_000
    transaction_wait_time_in_seconds: int = 20
    polling_wait_time_in_seconds: int = 1
    wait_for_transaction: bool = True


@dataclass
class SupraClientConfig(TransactionConfig, ApiClientConfig):
    """Configuration for the Supra client.

    This dataclass inherits from both `TransactionConfig` and `ApiClientConfig`, allowing a single object to hold both
    transaction-related parameters and API client connection settings.
    """


class SupraClient(
    AccountRestClient,
    TransactionRestClient,
    BlockRestClient,
    ConsensusRestClient,
    FaucetRestClient,
    GeneralRestClient,
):
    """Unified client for interacting with all Supra REST API endpoints, as well as generating and submitting
    transaction payloads in a seamless manner.

    This class acts as a single entry point for developers, combining multiple specialized REST clients into one unified
    interface. With `SupraClient`, you can access account information, submit and query transactions, retrieve block
    data, inspect consensus status, request testnet funds from the faucet, and query other general network information —
    all from a single client instance.

    In addition to REST API access, `SupraClient` provides a convenient set of methods for constructing various types of
    transaction payloads and handling transaction submission. This significantly simplifies the end-to-end process of
    building, signing, and submitting transactions to the Supra network.

    Attributes:
        _chain_id (int | None): The chain-id of the network.
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    _chain_id: int | None
    transaction_config: TransactionConfig

    def __init__(
        self, base_url: str, supra_client_config: SupraClientConfig | None = None
    ):
        """Initializes the REST client.

        Args:
            base_url (str): The base URL of the API.
            supra_client_config (SupraClientConfig): Configuration options for requests.

        """
        self._chain_id = None
        supra_client_config = supra_client_config or SupraClientConfig()

        transaction_config = TransactionConfig(
            expiration_ttl=supra_client_config.expiration_ttl,
            gas_unit_price=supra_client_config.gas_unit_price,
            max_gas_amount=supra_client_config.max_gas_amount,
            transaction_wait_time_in_seconds=supra_client_config.transaction_wait_time_in_seconds,
            polling_wait_time_in_seconds=supra_client_config.polling_wait_time_in_seconds,
            wait_for_transaction=supra_client_config.wait_for_transaction,
        )
        self.transaction_config = transaction_config

        api_client_config = ApiClientConfig(
            http2=supra_client_config.http2,
            access_token=supra_client_config.access_token,
        )
        super().__init__(ApiClient(base_url, api_client_config))

    async def close(self):
        """Closes the HTTP client session."""
        await self.api_client.close()

    async def chain_id(self):
        """Provides the network Chain-ID.

        Returns:
            int: Network Chain-ID.

        """
        if not self._chain_id:
            self._chain_id = await self.network_chain_id()
        return self._chain_id

    async def account_supra_balance(self, account_address: AccountAddress) -> int:
        """Provides the Supra coin balance associated with the given account.

        Args:
            account_address (AccountAddress): Address of the account.

        Returns:
            int: The Supra coin balance associated with the given account.

        """
        return await self.account_coin_balance(
            account_address, "0x1::supra_coin::SupraCoin"
        )

    async def account_coin_balance(
        self,
        account_address: AccountAddress,
        coin_type: str,
    ) -> int:
        """Provides the given `coin_type` coin balance associated with the given account.

        Args:
            account_address (AccountAddress): Address of the account.
            coin_type (str): The type of the coin for which balance needs to be provided.

        Returns:
            int: The given `coin_type` coin balance associated with the given account.

        """
        response = await self.view(
            "0x1::coin::balance", [coin_type], [str(account_address)]
        )
        return int(response[0])

    async def account_sequence_number(
        self,
        account_address: AccountAddress,
    ) -> int:
        """Provides the current sequence number of the given account.

        Args:
            account_address (AccountAddress): Address of the account.

        Returns:
            int: The current sequence number for the given account.

        """
        response = await self.account(account_address)
        return int(response["sequence_number"])

    async def submit_transaction(
        self,
        signed_transaction: SignedTransaction,
    ) -> str:
        """Submits a given signed transaction to the Supra network.

        This method wraps the given `signed_transaction` under `SupraTransaction`, serializes wrapped object using
        BCS serialization, submits serialized payload on the rpc node endpoint, and returns the transaction hash.

        Args:
            signed_transaction (SignedTransaction): Signed transaction object to submit transaction.

        Returns:
            str: Transaction hash of the submitted transaction.

        """
        transaction_hash = await self.submit(
            SupraTransaction(signed_transaction).to_bytes()
        )
        if self.transaction_config.wait_for_transaction:
            await self.wait_for_transaction(transaction_hash)
        return transaction_hash

    async def wait_for_transaction(self, tx_hash: str) -> dict[str, Any]:
        """Wait for a transaction till it's in a pending state and transaction wait timeout is not reached.

        This method repeatedly checks the transaction status until it is no longer pending or until the configured
        timeout is reached. Returns the transaction data regardless of success or failure status.

        Args:
            tx_hash (str): The hash of the transaction to wait for.

        Returns:
            dict[str, Any]: The final transaction data once the transaction is no longer pending.

        """
        start_time = time.monotonic()
        while (
            int(time.monotonic() - start_time)
            <= self.transaction_config.transaction_wait_time_in_seconds
        ):
            await asyncio.sleep(self.transaction_config.polling_wait_time_in_seconds)
            transaction_data = await self.transaction_by_hash(tx_hash)
            if transaction_data.get("status") != "Pending":
                return transaction_data

        raise TransactionWaitTimeoutReachedError(
            tx_hash, self.transaction_config.transaction_wait_time_in_seconds
        )

    async def simulate_transaction(
        self, signed_transaction: SignedTransaction
    ) -> dict[str, Any]:
        """Simulates a given signed transaction.

        This method internally replaces valid signatures with null/invalid signatures in the signed transaction payload,
        once simulation is completed, valid signatures are replaced with invalid signatures, hence, there is no need to
        provide a payload with invalid signatures.

        Args:
            signed_transaction (SignedTransaction): Signed transaction object for simulation simulate.

        Returns:
            dict[str, Any]: Transaction simulation result.

        """
        authenticator_with_valid_signature = signed_transaction.authenticator
        authenticator_clone = copy.deepcopy(signed_transaction.authenticator)
        authenticator_clone.unset_signature()
        signed_transaction.authenticator = authenticator_clone

        simulation_result = await self.simulate(
            SupraTransaction(signed_transaction).to_bytes()
        )
        signed_transaction.authenticator = authenticator_with_valid_signature
        return simulation_result

    async def create_raw_transaction(
        self,
        sender: Account | AccountAddress,
        transaction_payload: TransactionPayload,
        sequence_number: int | None = None,
    ) -> RawTransaction:
        """Creates a raw transaction.

        This method builds a raw transaction with the provided sender, payload, and optionally a custom sequence number.

        Args:
            sender (Account | AccountAddress): The account object or its address.
            transaction_payload (TransactionPayload): The transaction payload.
            sequence_number (int | None): The sender's sequence number. If not provided, it will be fetched
                automatically. Default to None.

        Returns:
            RawTransaction: The constructed raw transaction object.

        """
        sender_address = sender.address() if isinstance(sender, Account) else sender
        sequence_number = sequence_number or await self.account_sequence_number(
            sender_address
        )
        return RawTransaction(
            sender_address,
            sequence_number,
            transaction_payload,
            self.transaction_config.max_gas_amount,
            self.transaction_config.gas_unit_price,
            int(time.time()) + self.transaction_config.expiration_ttl,
            await self.chain_id(),
        )

    async def create_signed_transaction(
        self,
        sender: Account,
        transaction_payload: TransactionPayload,
        sequence_number: int | None = None,
    ) -> SignedTransaction:
        """Creates a signed transaction.

        This method builds a raw transaction, signs it using the sender's key, wraps it in an authenticator,
        and generates signed transaction payload.

        Args:
            sender (Account): The account signing the transaction.
            transaction_payload (TransactionPayload): The transaction payload.
            sequence_number (int | None): The sequence number to use. If not provided, the current sequence number will
                be fetched. Default to None.

        Returns:
            SignedTransaction: The constructed signed transaction object.

        """
        raw_transaction = await self.create_raw_transaction(
            sender, transaction_payload, sequence_number
        )
        authenticator = sender.sign_transaction(raw_transaction)
        return SignedTransaction(raw_transaction, authenticator)

    async def create_fee_payer_transaction(
        self,
        sender: Account,
        fee_payer: Account,
        secondary_accounts: list[Account],
        transaction_payload: TransactionPayload,
    ) -> SignedTransaction:
        """Creates a fee-payer authenticator type signed transaction.

        This method builds and signs a fee-payer authenticator type transaction, where the main sender, fee payer and
        one or more secondary accounts sign the same raw transaction.

        Args:
            sender (Account): The primary account sending the transaction.
            fee_payer (Account): The fee payer account to pay transaction fee.
            secondary_accounts (list[Account]): The secondary accounts that also authorize the transaction.
            transaction_payload (TransactionPayload): The transaction payload.

        Returns:
            SignedTransaction: The constructed multi-agent authenticator type signed transaction.

        """
        fee_payer_raw_transaction = FeePayerRawTransaction(
            await self.create_raw_transaction(sender, transaction_payload),
            [x.address() for x in secondary_accounts],
            fee_payer.address(),
        )
        authenticator = Authenticator(
            FeePayerAuthenticator(
                sender.sign_transaction(fee_payer_raw_transaction),
                [
                    (
                        x.address(),
                        x.sign_transaction(fee_payer_raw_transaction),
                    )
                    for x in secondary_accounts
                ],
                (
                    fee_payer.address(),
                    fee_payer.sign_transaction(fee_payer_raw_transaction),
                ),
            )
        )
        return SignedTransaction(fee_payer_raw_transaction.inner(), authenticator)

    async def create_multi_agent_transaction(
        self,
        sender: Account,
        secondary_accounts: list[Account],
        transaction_payload: TransactionPayload,
    ) -> SignedTransaction:
        """Creates a multi-agent authenticator type signed transaction.

        This method builds and signs a multi-agent authenticator type transaction, where the main sender and one or
        more secondary accounts sign the same raw transaction.

        Args:
            sender (Account): The primary account sending the transaction.
            secondary_accounts (list[Account]): The secondary accounts that also authorize the transaction.
            transaction_payload (TransactionPayload): The transaction payload.

        Returns:
            SignedTransaction: The constructed multi-agent authenticator type signed transaction.

        """
        multi_agent_raw_transaction = MultiAgentRawTransaction(
            await self.create_raw_transaction(sender, transaction_payload),
            [x.address() for x in secondary_accounts],
        )
        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender.sign_transaction(multi_agent_raw_transaction),
                [
                    (
                        x.address(),
                        x.sign_transaction(multi_agent_raw_transaction),
                    )
                    for x in secondary_accounts
                ],
            )
        )
        return SignedTransaction(multi_agent_raw_transaction.inner(), authenticator)

    async def register_automation_task(
        self,
        owner_account: Account,
        automated_function: EntryFunction,
        automation_max_gas_amount: int,
        automation_gas_price_cap: int,
        automation_fee_cap_for_epoch: int,
        automation_expiration_timestamp_secs: int,
        automation_aux_data: list[bytes],
    ) -> str:
        """Registers Supra automation task.

        Args:
            owner_account (Account): Account registering an automation task.
                It will be eligible to cancel or stop task.
            automated_function (str): Automated entry function payload.
            automation_max_gas_amount (int): Max gas allowed for automation.
            automation_gas_price_cap (int): Gas price cap for automation execution.
            automation_fee_cap_for_epoch (int): Maximum total fee for the epoch.
            automation_expiration_timestamp_secs (int): Expiration time for automation.
            automation_aux_data (list[bytes]): Auxiliary data for automation.

        Returns:
            str: Transaction hash.

        """
        automation_params_v1 = AutomationRegistrationParamsV1(
            automated_function,
            automation_max_gas_amount,
            automation_gas_price_cap,
            automation_fee_cap_for_epoch,
            automation_expiration_timestamp_secs,
            automation_aux_data,
        )
        transaction_payload = TransactionPayload(
            AutomationRegistrationParams(automation_params_v1)
        )
        signed_transaction = await self.create_signed_transaction(
            owner_account,
            transaction_payload,
        )
        return await self.submit_transaction(signed_transaction)

    async def cancel_automation_task(
        self,
        owner_account: Account,
        task_index: int,
    ) -> str:
        """Cancels Supra automation task.

        Args:
            owner_account (Account): Automation task owner.
            task_index (int): The ID of the automation task.

        Returns:
            str: Transaction hash.

        """
        transaction_arguments = [
            TransactionArgument(task_index, Serializer.u64),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::automation_registry",
            "cancel_task",
            [],
            transaction_arguments,
        )
        signed_transaction = await self.create_signed_transaction(
            owner_account,
            TransactionPayload(transaction_payload),
        )
        return await self.submit_transaction(signed_transaction)

    async def stop_automation_tasks(
        self,
        owner_account: Account,
        task_ids: list[int],
    ) -> str:
        """Stops list of Supra automation tasks.

        Args:
            owner_account (Account): Automation task owner.
            task_ids (list[int]): List of automation task IDs.

        Returns:
            str: Transaction hash.

        """
        transaction_arguments = [
            TransactionArgument(
                task_ids, Serializer.sequence_serializer(Serializer.u64)
            ),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::automation_registry",
            "stop_tasks",
            [],
            transaction_arguments,
        )
        signed_transaction = await self.create_signed_transaction(
            owner_account,
            TransactionPayload(transaction_payload),
        )
        return await self.submit_transaction(signed_transaction)

    async def transfer_supra_coin(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: int | None = None,
    ) -> str:
        """Transfers given amount of SupraCoin to a given recipient.

        This method builds an `EntryFunction` payload for transferring the `SupraCoin`, signs it with the sender's
        account, and submits it to the network.

        Args:
            sender (Account): Sender account.
            recipient (AccountAddress): Recipient account address.
            amount (int): The amount of coins to transfer.
            sequence_number (int | None): The sender's sequence number. If not provided, it will be fetched
                automatically. Default to None.

        Returns:
            str: Transaction hash.

        """
        return await self.transfer_coins(
            sender, recipient, "0x1::supra_coin::SupraCoin", amount, sequence_number
        )

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: int | None = None,
    ) -> str:
        """Transfer a given coin type coins to a recipient.

        This method builds a coin transfer payload for any supported coin type, signs it with the sender's account,
        and submits it to the network.

        Args:
            sender (Account): Sender account.
            recipient (AccountAddress): Recipient account address.
            coin_type (str): The fully-qualified coin type tag e.g. '0x1::supra_coin::SupraCoin'.
            amount (int): The amount of coins to transfer.
            sequence_number (int | None): The sender's sequence number. If not provided, it will be fetched
                automatically. Default to None.

        Returns:
            str: Transaction hash.

        """
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::supra_account",
            "transfer_coins",
            [TypeTag(StructTag.from_str(coin_type))],
            transaction_arguments,
        )
        signed_transaction = await self.create_signed_transaction(
            sender, TransactionPayload(transaction_payload), sequence_number
        )
        return await self.submit_transaction(signed_transaction)

    async def transfer_object(
        self, owner: Account, object_address: AccountAddress, to: AccountAddress
    ) -> str:
        """Transfer an object to another account.

        This method builds an object transfer payload, signs it with the owner's account, and submits it to the network.

        Args:
            owner (Account): The owner account sending the object.
            object_address (AccountAddress): The address of the object to transfer.
            to (AccountAddress): The recipient's account address.

        Returns:
            str: Transaction hash.

        """
        transaction_arguments = [
            TransactionArgument(object_address, Serializer.struct),
            TransactionArgument(to, Serializer.struct),
        ]
        payload = EntryFunction.natural(
            "0x1::object",
            "transfer_call",
            [],
            transaction_arguments,
        )
        signed_transaction = await self.create_signed_transaction(
            owner,
            TransactionPayload(payload),
        )
        return await self.submit_transaction(signed_transaction)

    async def publish_package(
        self, module_publisher: Account, package_metadata: bytes, modules: list[bytes]
    ) -> str:
        """Publishes package on a given module publisher account.

        Args:
            module_publisher (Account): Module publisher account.
            package_metadata (bytes): Metadata of the package, generated after package compilation.
            modules (list[bytes]): List of package's module bytecode .

        Returns:
            str: Transaction hash.

        """
        transaction_arguments = [
            TransactionArgument(package_metadata, Serializer.to_bytes),
            TransactionArgument(
                modules, Serializer.sequence_serializer(Serializer.to_bytes)
            ),
        ]
        payload = EntryFunction.natural(
            "0x1::code",
            "publish_package_txn",
            [],
            transaction_arguments,
        )
        signed_transaction = await self.create_signed_transaction(
            module_publisher, TransactionPayload(payload)
        )
        return await self.submit_transaction(signed_transaction)

    async def faucet(
        self, address: AccountAddress, wait_for_faucet: bool = True
    ) -> str | None:
        """Requests faucet funds to be sent to the given account address.

        Args:
            address (AccountAddress): The target account address to receive funds.
            wait_for_faucet (bool): Flag indicates whether wait for faucet should be done or not. Default to True.

        Returns:
            str | None: Faucet transaction hash if faucet request is accepted else None.

        """
        may_be_tx_hash = await self.fund_with_faucet(address)
        if wait_for_faucet:
            if not may_be_tx_hash:
                raise FaucetRequestNotAcceptedError
            await self.wait_for_faucet(may_be_tx_hash)
        return may_be_tx_hash

    async def wait_for_faucet(self, faucet_tx_hash: str) -> dict[str, Any]:
        """Wait for a faucet transaction till it's in a pending state and transaction wait timeout is not reached.

        Note: This method is similar to the `SupraClient.wait_for_transaction`, this method uses
        `FaucetClient.faucet_transaction_by_hash` method to get transaction data of the faucet transaction, it uses that
        method because, there is different endpoint meant in rpc node to get the transaction details of the pending
        faucet transactions.

        Args:
            faucet_tx_hash (str): The hash of the faucet transaction to wait for.

        Returns:
            dict[str, Any]: The final transaction data once the faucet transaction is no longer pending.

        """
        start_time = time.monotonic()
        while (
            int(time.monotonic() - start_time)
            <= self.transaction_config.transaction_wait_time_in_seconds
        ):
            await asyncio.sleep(self.transaction_config.polling_wait_time_in_seconds)
            transaction_data = await self.faucet_transaction_by_hash(faucet_tx_hash)
            if transaction_data.get("status") != "Pending":
                return transaction_data

        raise TransactionWaitTimeoutReachedError(
            faucet_tx_hash,
            self.transaction_config.transaction_wait_time_in_seconds,
        )


class TransactionWaitTimeoutReachedError(Exception):
    """Exception raised when the transaction is in 'Pending' state even after max transaction wait time.

    Attributes:
        tx_hash (str): Transaction hash.

    """

    def __init__(self, tx_hash: str, transaction_wait_time_in_seconds: int):
        """Initializes the exception with transaction hash and wait time.

        Args:
            tx_hash (str): Transaction hash
            transaction_wait_time_in_seconds (int): Transaction wait time.

        """
        self.tx_hash = tx_hash
        super().__init__(
            f"{tx_hash} transaction didn't processed within {transaction_wait_time_in_seconds} seconds"
        )


class FaucetRequestNotAcceptedError(Exception):
    """Exception raised when faucet request is not accepted by the faucet rpc node."""

    def __init__(self):
        """Initializes the exception with a default message."""
        super().__init__("Faucet request is not accepted by the rpc node")
