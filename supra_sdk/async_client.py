# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import copy
import json
import time
import unittest
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Union, cast
from urllib.parse import urljoin

import httpx

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.api_types import (
    ACCOUNT_AUTOMATED_TRANSACTIONS_ENDPOINT,
    ACCOUNT_COIN_TRANSACTIONS_ENDPOINT,
    ACCOUNT_ENDPOINT,
    ACCOUNT_MODULE_ENDPOINT,
    ACCOUNT_MODULES_ENDPOINT,
    ACCOUNT_RESOURCE_ENDPOINT,
    ACCOUNT_RESOURCES_ENDPOINT,
    ACCOUNT_TRANSACTIONS_ENDPOINT,
    BLOCK_BY_HASH_ENDPOINT,
    BLOCK_BY_HEIGHT_ENDPOINT,
    BLOCK_TRANSACTIONS_ENDPOINT,
    CHAIN_ID_ENDPOINT,
    COMMITTEE_AUTHORIZATION_ENDPOINT,
    CONSENSUS_BLOCK_BY_HEIGHT_ENDPOINT,
    EVENTS_BY_TYPE_ENDPOINT,
    FAUCET_ENDPOINT,
    FAUCET_TRANSACTION_ENDPOINT,
    LATEST_BLOCK_ENDPOINT,
    LATEST_CONSENSUS_BLOCK_ENDPOINT,
    TABLE_ITEMS_ENDPOINT,
    TRANSACTION_BY_HASH_ENDPOINT,
    TRANSACTION_ESTIMATE_GAS_PRICE_ENDPOINT,
    TRANSACTION_PARAMETERS_ENDPOINT,
    TRANSACTION_SIMULATE_TRANSACTION_ENDPOINT,
    TRANSACTION_SUBMIT_TRANSACTION_ENDPOINT,
    VIEW_FUNCTION_ENDPOINT,
    AutomatedTransactionsPagination,
    EventsPagination,
    Pagination,
    PaginationWithOrder,
    TransactionType,
)
from supra_sdk.authenticator import (
    Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
)
from supra_sdk.bcs import Serializer
from supra_sdk.metadata import Metadata
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
class ClientConfig:
    """
    Holds configuration options for REST API clients.

    Attributes:
        expiration_ttl (int): Time-to-live in seconds before a transaction expires.
        gas_unit_price (int): Price per unit of gas.
        max_gas_amount (int): Maximum gas units allowed for transactions.
        transaction_wait_time_in_seconds (int): Time to wait for transaction confirmation.
        polling_wait_time_in_seconds (int): Time to wait in polling before next request.
        wait_for_transaction (bool): Flag indicating whether there should be a wait for sent transaction or not.
        http2 (bool): Whether to use HTTP/2 for requests.
        access_token (Optional[str]): Optional access token (JWT) for authentication.
    """

    expiration_ttl: int = 600
    gas_unit_price: int = 100
    max_gas_amount: int = 500_000
    transaction_wait_time_in_seconds: int = 20
    polling_wait_time_in_seconds: int = 1
    wait_for_transaction: bool = True
    http2: bool = False
    access_token: Optional[str] = None

    def raise_if_access_token_not_exists(self):
        if not self.access_token:
            raise AuthorizationKeyNotSpecified


class RestClient:
    """Allows to interact with the Supra-L1 Rest API in seamless manner"""

    _chain_id: Optional[int]
    client: httpx.AsyncClient
    client_config: ClientConfig
    base_url: str

    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
        """
        Initializes the REST client.

        Args:
            base_url (str): The base URL of the API.
            client_config (ClientConfig): Configuration options for requests.
        """

        self.base_url = base_url
        # Default limits
        limits = httpx.Limits()
        # Default timeouts but do not set a pool timeout, since the idea is that jobs will wait as
        # long as progress is being made.
        timeout = httpx.Timeout(60.0, pool=None)
        # Default headers
        headers = {Metadata.SUPRA_HEADER: Metadata.get_supra_header_val()}
        self.client = httpx.AsyncClient(
            http2=client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=headers,
        )
        self.client_config = client_config
        self._chain_id = None

    async def close(self):
        """
        Closes the HTTP client session.
        """

        await self.client.aclose()

    async def chain_id(self):
        """
        Provides the network Chain-ID.

        Returns:
            int: Network Chain-ID.
        """

        if not self._chain_id:
            response = await self._get(endpoint=CHAIN_ID_ENDPOINT)
            self._chain_id = int(response.text)
        return self._chain_id

    async def account(
        self,
        account_address: AccountAddress,
    ) -> Dict[str, str]:
        """
        Provides the authentication key and the sequence number of the given account.

        Args:
            account_address (AccountAddress): Address of the account.

        Returns:
            Dict[str, str]: The authentication key and sequence number of the given account.
        """

        endpoint = ACCOUNT_ENDPOINT.format(account_address=account_address)
        return (await self._get(endpoint=endpoint)).json()

    async def account_supra_balance(self, account_address: AccountAddress) -> int:
        """
        Provides the Supra coin balance associated with the given account.

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
        """
        Provides the given `coin_type` coin balance associated with the given account.

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
        """
        Provides the current sequence number of the given account.

        Args:
            account_address (AccountAddress): Address of the account.

        Returns:
            int: The current sequence number for the given account.
        """

        response = await self.account(account_address)
        return int(response["sequence_number"])

    async def account_resource(
        self,
        account_address: AccountAddress,
        resource_type: str,
    ) -> Dict[str, Any]:
        """
        Retrieves an individual resource from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            resource_type (str): Type of the resource e.g. '0x1::account::Account'.

        Returns:
            Dict[str, Any]: An individual resource from a given account.
        """

        endpoint = ACCOUNT_RESOURCE_ENDPOINT.format(
            account_address=account_address, resource_type=resource_type
        )
        return (await self._get(endpoint=endpoint)).json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        pagination: Optional[Pagination] = None,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves all account resources for a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Optional[Pagination]): Pagination options.

        Returns:
            Tuple[List[Dict[str, Any]], str]: A tuple containing,
                - List[Dict[str, Any]]: All account resources for a given account.
                - str: Cursor to retrieve the next page.
        """

        endpoint = ACCOUNT_RESOURCES_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        response = await self._get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_module(
        self,
        account_address: AccountAddress,
        module_name: str,
    ) -> Dict[str, Any]:
        """
        Retrieves an individual module from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            module_name (str): Name of the module to retrieve e.g. 'account'

        Returns:
            Dict[str, Any]: An individual module from a given account.
        """

        endpoint = ACCOUNT_MODULE_ENDPOINT.format(
            account_address=account_address, module_name=module_name
        )
        return (await self._get(endpoint=endpoint)).json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        pagination: Optional[Pagination] = None,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves all account modules from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Optional[Pagination]): Pagination options.

        Returns:
            Tuple[List[Dict[str, Any]], str]: A tuple containing,
                - List[Dict[str, Any]]: All account modules from a given account.
                - str: Cursor to retrieve the next page.
        """

        endpoint = ACCOUNT_MODULES_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        response = await self._get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_transactions(
        self,
        account_address: AccountAddress,
        pagination: Optional[PaginationWithOrder] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves details of finalized transactions sent by a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Optional[PaginationWithOrder]): Pagination options.
                Note: Sequence number would be used as start in pagination option.

        Returns:
            List[Dict[str, Any]]: Details of finalized transactions sent by a given account.
        """

        endpoint = ACCOUNT_TRANSACTIONS_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        return (await self._get(endpoint=endpoint, params=params)).json()

    async def account_coin_transactions(
        self,
        account_address: AccountAddress,
        pagination: Optional[PaginationWithOrder] = None,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves details of finalized coin deposit/withdraw type transactions associated with a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Optional[PaginationWithOrder]): Pagination options.

        Returns:
            Tuple[List[Dict[str, Any]], str]: A tuple containing,
                - List[Dict[str, Any]]: Details of finalized coin deposit/withdraw type transactions associated with a
                    given account.
                - str: Cursor to retrieve the next page.
        """

        endpoint = ACCOUNT_COIN_TRANSACTIONS_ENDPOINT.format(
            account_address=account_address
        )
        params = pagination.to_params() if pagination else {}
        response = await self._get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_automated_transactions(
        self,
        account_address: AccountAddress,
        pagination: Optional[AutomatedTransactionsPagination] = None,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves details of finalized automated transactions based on the automation tasks registered by a given
        account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Optional[AutomatedTransactionsPagination]): Pagination options.

        Returns:
            Tuple[List[Dict[str, any]], str]: A tuple containing,
                - List[Dict[str, any]]: Details of finalized automated transactions details based on the automation
                    tasks registered by a given account.
                - str: Cursor to retrieve the next page.
        """

        endpoint = ACCOUNT_AUTOMATED_TRANSACTIONS_ENDPOINT.format(
            account_address=account_address
        )
        params = pagination.to_params() if pagination else {}
        response = await self._get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def transaction_by_hash(self, tx_hash: str) -> Dict[str, Any]:
        """
        Retrieves detail of a transaction by given transaction hash.

        Args:
            tx_hash (str): The hash of the transaction.

        Returns:
            Dict[str, Any]: Detail of a transaction by given transaction hash.
        """

        endpoint = TRANSACTION_BY_HASH_ENDPOINT.format(hash=tx_hash)
        return (await self._get(endpoint=endpoint)).json()

    async def estimate_gas_price(self) -> Dict[str, Any]:
        """
        Provides statistics derived from the gas prices of recently executed transactions.

        Returns:
            Dict[str, Any]: Statistics derived from the gas prices of recently executed transactions.
        """

        return (
            await self._get(endpoint=TRANSACTION_ESTIMATE_GAS_PRICE_ENDPOINT)
        ).json()

    async def transaction_parameters(self) -> Dict[str, Any]:
        """
        Retrieve limits that a client must respect when composing a transaction.

        Returns:
            Dict[str, Any]: limits that a client must respect when composing a transaction.
        """

        return (await self._get(endpoint=TRANSACTION_PARAMETERS_ENDPOINT)).json()

    async def submit_transaction(
        self,
        signed_transaction: SignedTransaction,
    ) -> str:
        """
        Submits a given signed transaction to the Supra network.

        This method wraps the given `signed_transaction` under `SupraTransaction`, serializes wrapped object using
        BCS serialization, submits serialized payload on the rpc node endpoint, and returns the transaction hash.

        Args:
            signed_transaction (SignedTransaction): Signed transaction object to submit transaction.

        Returns:
            str: Transaction hash of the submitted transaction.
        """

        headers = {"Content-Type": "application/x.supra.signed_transaction+bcs"}
        response = await self._post(
            endpoint=TRANSACTION_SUBMIT_TRANSACTION_ENDPOINT,
            data=SupraTransaction(signed_transaction).to_bytes(),
            headers=headers,
        )
        transaction_hash = response.json()
        if self.client_config.wait_for_transaction:
            await self.wait_for_transaction(transaction_hash)
        return transaction_hash

    async def wait_for_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """
        Wait for a transaction till it's in a pending state and transaction wait timeout is not reached.

        This method repeatedly checks the transaction status until it is no longer pending or until the configured
        timeout is reached. Returns the transaction data regardless of success or failure status.

        Args:
            tx_hash (str): The hash of the transaction to wait for.

        Returns:
            Dict[str, Any]: The final transaction data once the transaction is no longer pending.
        """

        start_time = time.monotonic()
        while (
            int(time.monotonic() - start_time)
            <= self.client_config.transaction_wait_time_in_seconds
        ):
            await asyncio.sleep(self.client_config.polling_wait_time_in_seconds)
            transaction_data = await self.transaction_by_hash(tx_hash)
            if transaction_data.get("status") != "Pending":
                return transaction_data

        raise TransactionWaitTimeoutReached(
            tx_hash, self.client_config.transaction_wait_time_in_seconds
        )

    async def simulate_transaction(
        self, signed_transaction: SignedTransaction
    ) -> Dict[str, Any]:
        """
        Simulates a given signed transaction.

        Currently, it is expected that signatures of authenticator will be null/invalid instead of being valid.

        Args:
            signed_transaction (SignedTransaction): Signed transaction object for simulation simulate.

        Returns:
            Dict[str, Any]: Transaction simulation result.
        """

        authenticator_with_valid_signature = signed_transaction.authenticator
        authenticator_clone = copy.deepcopy(signed_transaction.authenticator)
        authenticator_clone.unset_signature()
        signed_transaction.authenticator = authenticator_clone

        headers = {"Content-Type": "application/x.supra.signed_transaction+bcs"}
        response = await self._post(
            endpoint=TRANSACTION_SIMULATE_TRANSACTION_ENDPOINT,
            data=SupraTransaction(signed_transaction).to_bytes(),
            headers=headers,
        )
        simulation_result = response.json()
        signed_transaction.authenticator = authenticator_with_valid_signature
        return simulation_result

    async def create_raw_transaction(
        self,
        sender: Union[Account, AccountAddress],
        transaction_payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> RawTransaction:
        """
        Creates a raw transaction.

        This method builds a raw transaction with the provided sender, payload, and optionally a custom sequence number.

        Args:
            sender (Union[Account, AccountAddress]): The account object or its address.
            transaction_payload (TransactionPayload): The transaction payload.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

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
            self.client_config.max_gas_amount,
            self.client_config.gas_unit_price,
            int(time.time()) + self.client_config.expiration_ttl,
            await self.chain_id(),
        )

    async def create_signed_transaction(
        self,
        sender: Account,
        transaction_payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> SignedTransaction:
        """
        Creates a signed transaction.

        This method builds a raw transaction, signs it using the sender's key, wraps it in an authenticator,
        and generates signed transaction payload.

        Args:
            sender (Account): The account signing the transaction.
            transaction_payload (TransactionPayload): The transaction payload.
            sequence_number (Optional[int], optional): The sequence number to use.
                If not provided, the current sequence number will be fetched.

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
        secondary_accounts: List[Account],
        transaction_payload: TransactionPayload,
    ) -> SignedTransaction:
        """
        Creates a fee-payer authenticator type signed transaction.

        This method builds and signs a fee-payer authenticator type transaction, where the main sender, fee payer and
        one or more secondary accounts sign the same raw transaction.

        Args:
            sender (Account): The primary account sending the transaction.
            fee_payer (Account): The fee payer account to pay transaction fee.
            secondary_accounts (List[Account]): The secondary accounts that also authorize the transaction.
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
        secondary_accounts: List[Account],
        transaction_payload: TransactionPayload,
    ) -> SignedTransaction:
        """
        Creates a multi-agent authenticator type signed transaction.

        This method builds and signs a multi-agent authenticator type transaction, where the main sender and one or
        more secondary accounts sign the same raw transaction.

        Args:
            sender (Account): The primary account sending the transaction.
            secondary_accounts (List[Account]): The secondary accounts that also authorize the transaction.
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
        automation_aux_data: List[bytes],
    ) -> str:
        """
        Registers Supra automation task.

        Args:
            owner_account (Account): Account registering an automation task.
                It will be eligible to cancel or stop task.
            automated_function (str): Automated entry function payload.
            automation_max_gas_amount (int): Max gas allowed for automation.
            automation_gas_price_cap (int): Gas price cap for automation execution.
            automation_fee_cap_for_epoch (int): Maximum total fee for the epoch.
            automation_expiration_timestamp_secs (int): Expiration time for automation.
            automation_aux_data (List[bytes]): Auxiliary data for automation.

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
    ) -> Union[Dict[str, Any], str]:
        """
        Cancels Supra automation task.

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
        task_ids: List[int],
    ) -> Union[Dict[str, Any], str]:
        """
        Stops list of Supra automation tasks.

        Args:
            owner_account (Account): Automation task owner.
            task_ids (List[int]): List of automation task IDs.

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
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfers given amount of SupraCoin to a given recipient.

        This method builds an `EntryFunction` payload for transferring the `SupraCoin`, signs it with the sender's
        account, and submits it to the network.

        Args:
            sender (Account): Sender account.
            recipient (AccountAddress): Recipient account address.
            amount (int): The amount of coins to transfer.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

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
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer a given coin type coins to a recipient.

        This method builds a coin transfer payload for any supported coin type, signs it with the sender's account,
        and submits it to the network.

        Args:
            sender (Account): Sender account.
            recipient (AccountAddress): Recipient account address.
            coin_type (str): The fully-qualified coin type tag e.g. '0x1::supra_coin::SupraCoin'.
            amount (int): The amount of coins to transfer.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

        Returns:
            str: Transaction hash.
        """

        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
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
        """
        Transfer an object to another account.

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
        self, module_publisher: Account, package_metadata: bytes, modules: List[bytes]
    ) -> str:
        """
        Publishes package on a given module publisher account.

        Args:
            module_publisher (Account): Module publisher account.
            package_metadata (bytes): Metadata of the package, generated after package compilation.
            modules (List[bytes]): List of package's module bytecode .

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

    async def view(
        self,
        function: str,
        type_arguments: List[str],
        arguments: List[str],
    ) -> List[Any]:
        """
        Execute a view Move function with the given parameters and return its execution result.

        Args:
            function (str): Entry function id is string representation of an entry function defined on-chain.
            type_arguments (List[str]): Type arguments of the function.
            arguments (List[str]): Arguments of the function.

        Returns:
            List[Any]: Execution results of the view function.
        """

        data = {
            "function": function,
            "type_arguments": type_arguments,
            "arguments": arguments,
        }
        return ((await self._post(endpoint=VIEW_FUNCTION_ENDPOINT, data=data)).json())[
            "result"
        ]

    async def get_table_item(
        self,
        table_handle: str,
        key_type: str,
        value_type: str,
        key: Any,
    ) -> Dict[str, Any]:
        """
        Retrieves an item from a table by key.

        Args:
            table_handle (str): Table handle to lookup. Should be retrieved using account resources API.
            key_type (str): The type of the table key.
            value_type (str): The type of the table value.
            key (str): The key to fetch from the table.

        Returns:
            Dict[str, Any]: Item associated with the key in the table.
        """

        endpoint = TABLE_ITEMS_ENDPOINT.format(table_handle=table_handle)
        data = {
            "key_type": key_type,
            "value_type": value_type,
            "key": key,
        }
        return (await self._post(endpoint=endpoint, data=data)).json()

    async def events_by_type(
        self, event_type: str, pagination: Optional[EventsPagination] = None
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves events of a given type.

        Args:
            event_type (str): The fully qualified name of the event struct e.g. '0x1::coin::CoinDeposit'.
            pagination (Optional[EventsPagination]): Pagination options.

        Returns:
            Tuple[List[Dict[str, Any]], str]: A tuple containing,
                - List[Dict[str, Any]]: List of events.
                - str: Cursor to retrieve the next page.
        """

        endpoint = EVENTS_BY_TYPE_ENDPOINT.format(event_type=event_type)
        params = pagination.to_params() if pagination else {}
        response = await self._get(endpoint=endpoint, params=params)
        return response.json()["data"], response.headers.get("x-supra-cursor", "")

    async def latest_block(self) -> Dict[str, Any]:
        """
        Retrieves the metadata information of the most recently finalized and executed block.

        Returns:
            Dict[str, Any]: Metadata information of the most recently finalized and executed block.
        """

        return (await self._get(endpoint=LATEST_BLOCK_ENDPOINT)).json()

    async def block_by_hash(self, block_hash: str) -> Dict[str, Any]:
        """
        Retrieves the header and execution output statistics of the block with the given hash.

        Args:
            block_hash (str): The hash of the block.

        Returns:
            Dict[str, Any]: Header and execution output statistics of the block with the given hash.
        """

        endpoint = BLOCK_BY_HASH_ENDPOINT.format(block_hash=block_hash)
        return (await self._get(endpoint=endpoint)).json()

    async def block_by_height(
        self,
        height: int,
        transaction_type: Optional[TransactionType] = None,
        with_finalized_transaction: bool = False,
    ) -> Dict[str, Any]:
        """
        Retrieves information about the block that has been finalized at the given height.

        Args:
            height (int): The height of the block.
            transaction_type (Optional[TransactionType]): Transaction type to query.
                If missing any/all type of transactions will be looked for.
            with_finalized_transaction (bool): Whether to include finalized transactions or not.

        Returns:
            Dict[str, Any]: Information about the block that has been finalized at the given height.
        """

        endpoint = BLOCK_BY_HEIGHT_ENDPOINT.format(height=height)
        params: Dict[str, Union[str, bool]] = {
            "with_finalized_transactions": with_finalized_transaction
        }
        if transaction_type:
            params["transaction_type"] = transaction_type.value
        return (await self._get(endpoint=endpoint, params=params)).json()

    async def txs_by_block(
        self, block_hash: str, transaction_type: Optional[TransactionType] = None
    ) -> List[str]:
        """
        Retrieves a list containing the hashes of the transactions that were finalized in the block with the given hash
        in the order that they were executed.

        Args:
            block_hash (str): The hash of the block.
            transaction_type (Optional[TransactionType]): Transaction type to query.
                If missing any/all type of transactions will be looked for.

        Returns:
            List[str]: List transaction's hash that were finalized in the given block.
        """

        endpoint = BLOCK_TRANSACTIONS_ENDPOINT.format(block_hash=block_hash)
        params = (
            {"transaction_type": transaction_type.value} if transaction_type else {}
        )
        return (await self._get(endpoint=endpoint, params=params)).json()

    async def latest_consensus_block(self) -> bytes:
        """
        Retrieves the BCS bytes of the latest consensus block.

        Returns:
             bytes: BCS bytes of the latest consensus block.
        """

        self.client_config.raise_if_access_token_not_exists()
        return (await self._get(endpoint=LATEST_CONSENSUS_BLOCK_ENDPOINT)).read()

    async def consensus_block_by_height(
        self, height: int, with_batches: bool = False
    ) -> bytes:
        """
        Retrieves the BCS bytes of the consensus block at the requested height.

        Args:
            height (int): The height of the consensus block to retrieve.
            with_batches (bool): If true, returns all batches of transactions with certificates contained in this block.

        Returns:
            bytes: BCS bytes of the consensus block at the requested height.
        """

        endpoint = CONSENSUS_BLOCK_BY_HEIGHT_ENDPOINT.format(height=height)
        params = {"with_batches": str(with_batches).lower()}
        return (await self._get(endpoint=endpoint, params=params)).read()

    async def committee_authorization(self, epoch: int) -> bytes:
        """
        Retrieves the BCS bytes of the Committee Authorization for the given epoch.

        Args:
            epoch (int): The epoch number.

        Returns:
            bytes: BCS bytes of the Committee Authorization for the requested epoch.
        """
        endpoint = COMMITTEE_AUTHORIZATION_ENDPOINT.format(epoch=epoch)
        return (await self._get(endpoint=endpoint)).read()

    """
    Helpers to send HTTP request
    """

    async def _get(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        strict_mode: Optional[bool] = True,
    ) -> httpx.Response:
        """
        Performs an asynchronous GET request.

        Args:
            endpoint (str): Endpoint to call.
            headers (Optional[Dict[str, str]]): Optional headers.
            params (Optional[Dict[str, Any]]): Optional query parameters.
            strict_mode (Optional[bool]): If enabled then raises an error when request response status code is not 200.

        Returns:
            httpx.Response: The response from the server.
        """

        params = params or {}
        params = {key: val for key, val in params.items() if val is not None}
        headers = headers or {}

        if self.client_config.access_token:
            headers["Authorization"] = f"Bearer {self.client_config.access_token}"

        response = await self.client.get(
            url=urljoin(self.base_url, endpoint), params=params, headers=headers
        )
        if strict_mode and response.status_code != HTTPStatus.OK:
            raise ApiError(response.text, response.status_code)
        return response

    async def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], bytes]] = None,
        strict_mode: Optional[bool] = True,
    ) -> httpx.Response:
        """
        Performs an asynchronous POST request.

        Args:
            endpoint (str): API endpoint.
            params (Optional[Dict[str, Any]]): Query parameters.
            headers (Optional[Dict[str, Any]]): Request headers.
            data (Optional[Union[Dict[str, Any], bytes]]): POST body data.
            strict_mode (Optional[bool]): If enabled then raises an error when request response status code is not 200.

        Returns:
            httpx.Response: The response from the server.
        """

        params = params or {}
        params = {key: val for key, val in params.items() if val is not None}
        headers = headers or {}

        content: Union[str, bytes]
        if not isinstance(data, bytes):
            headers["Content-Type"] = "application/json"
            content = json.dumps(data)
        else:
            content = cast(bytes, data)

        response = await self.client.post(
            url=urljoin(self.base_url, endpoint),
            params=params,
            headers=headers,
            content=content,
        )
        if strict_mode and response.status_code != HTTPStatus.OK:
            raise ApiError(response.text, response.status_code)
        return response


class FaucetClient:
    """Faucet creates and funds accounts. This is a thin wrapper around that."""

    base_url: str
    rest_client: RestClient

    def __init__(self, base_url: str, rest_client: RestClient):
        """
        Initializes the FaucetClient.

        Args:
            base_url (str): Faucet service URL.
            rest_client (RestClient): Instance of RestClient to use.
        """

        self.base_url = base_url
        self.rest_client = rest_client

    async def close(self):
        await self.rest_client.close()

    async def faucet(
        self, address: AccountAddress, wait_for_faucet: bool = True
    ) -> Optional[str]:
        """
        Requests faucet funds to be sent to the given account address.

        Args:
            address (AccountAddress): The target account address to receive funds.
            wait_for_faucet (bool): Flag indicates whether wait for faucet should be done or not.
        Returns:
            str: Faucet transaction hash if faucet request is accepted else None.
        """

        endpoint = FAUCET_ENDPOINT.format(address=address)
        res_data = (await self._get(endpoint=endpoint)).json()
        may_be_tx_hash = res_data["Accepted"] if "Accepted" in res_data else None
        if wait_for_faucet:
            if not may_be_tx_hash:
                raise FaucetRequestNotAccepted
            await self.wait_for_faucet(may_be_tx_hash)
        return may_be_tx_hash

    async def wait_for_faucet(self, faucet_tx_hash: str):
        """
        Wait for a faucet transaction till it's in a pending state and transaction wait timeout is not reached.

        Note: This method is similar to the `RestClient.wait_for_transaction`, this method uses
        `FaucetClient.faucet_transaction_by_hash` method to get transaction data of the faucet transaction, it uses that
         method because, there is different endpoint meant in rpc node to get the transaction details of the pending
         faucet transactions.

        Args:
            faucet_tx_hash (str): The hash of the faucet transaction to wait for.

        Returns:
            Dict[str, Any]: The final transaction data once the faucet transaction is no longer pending.
        """
        start_time = time.monotonic()
        while (
            int(time.monotonic() - start_time)
            <= self.rest_client.client_config.transaction_wait_time_in_seconds
        ):
            await asyncio.sleep(
                self.rest_client.client_config.polling_wait_time_in_seconds
            )
            transaction_data = await self.faucet_transaction_by_hash(faucet_tx_hash)
            if transaction_data.get("status") != "Pending":
                return transaction_data

        raise TransactionWaitTimeoutReached(
            faucet_tx_hash,
            self.rest_client.client_config.transaction_wait_time_in_seconds,
        )

    async def faucet_transaction_by_hash(self, tx_hash: str) -> Dict[str, Any]:
        """
        Retrieves details of a faucet transaction by its hash.

        Args:
            tx_hash (str): The hash of the faucet transaction.

        Returns:
            Dict[str, Any]: Faucet transaction details.
        """

        endpoint = FAUCET_TRANSACTION_ENDPOINT.format(hash=tx_hash)
        return (await self._get(endpoint=endpoint)).json()

    async def _get(
        self,
        endpoint: str,
    ) -> httpx.Response:
        """
        Performs an asynchronous GET request.

        Args:
            endpoint (str): Endpoint to call.

        Returns:
            httpx.Response: The response from the server.
        """

        response = await self.rest_client.client.get(
            url=urljoin(self.base_url, endpoint)
        )
        if response.status_code != HTTPStatus.OK:
            raise ApiError(response.text, response.status_code)
        return response


class ApiError(Exception):
    """
    Exception raised when the API returns a non-200 response.

    Attributes:
        status_code (int): The HTTP status code returned.
    """

    endpoint: str
    status_code: int

    def __init__(self, message: str, status_code: int):
        self.status_code = status_code
        super().__init__(f"{{message: {message}, status_code: {status_code}}}")


class TransactionWaitTimeoutReached(Exception):
    """
    Exception raised when the transaction is in 'Pending' state even after max transaction wait time.

    Attributes:
        tx_hash (str): Transaction hash.
    """

    def __init__(self, tx_hash: str, transaction_wait_time_in_seconds: int):
        self.tx_hash = tx_hash
        super().__init__(
            f"{tx_hash} transaction didn't processed within {transaction_wait_time_in_seconds} seconds"
        )


class AuthorizationKeyNotSpecified(Exception):
    """
    Exception raised when consensus api endpoints are accessed without defining `access_token` in `ClientConfig`.
    """

    def __init__(self):
        super().__init__("Authorization key is not specified")


class FaucetRequestNotAccepted(Exception):
    """
    Exception raised when faucet request is not accepted by the faucet rpc node.
    """

    def __init__(self):
        super().__init__("Faucet request is not accepted by the rpc node")


class TestRestClientEndpointsIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.test_account = Account.generate()
        self.rest_client = RestClient(base_url)
        self.faucet_client = FaucetClient(faucet_url, self.rest_client)

    async def test_account(self):
        account_info = await self.rest_client.account(AccountAddress.from_str("0x1"))
        self.assertEqual(account_info["sequence_number"], 0)
        self.assertEqual(
            account_info["authentication_key"],
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )

    async def test_account_supra_balance(self):
        self.assertEqual(
            await self.rest_client.account_supra_balance(self.test_account.address()),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertGreater(
            await self.rest_client.account_supra_balance(self.test_account.address()),
            0,
        )

    async def test_account_coin_balance(self):
        self.assertEqual(
            await self.rest_client.account_coin_balance(
                self.test_account.address(), "0x1::supra_coin::SupraCoin"
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertGreater(
            await self.rest_client.account_coin_balance(
                self.test_account.address(), "0x1::supra_coin::SupraCoin"
            ),
            0,
        )

    async def test_account_sequence_number(self):
        with self.assertRaisesRegex(
            expected_exception=ApiError,
            expected_regex="Resource not found: 0x1::account::Account",
        ):
            await self.rest_client.account_sequence_number(self.test_account.address())

        await self.faucet_client.faucet(self.test_account.address())
        self.assertEqual(
            await self.rest_client.account_sequence_number(self.test_account.address()),
            0,
        )

    async def test_account_resource(self):
        account_resource = await self.rest_client.account_resource(
            AccountAddress.from_str("0x1"), "0x1::account::Account"
        )
        self.assertEqual(account_resource["type"], "0x1::account::Account")

    async def test_account_resources(self):
        self.assertGreater(
            len(
                (
                    await self.rest_client.account_resources(
                        AccountAddress.from_str("0x1")
                    )
                )[0]
            ),
            1,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_resources(
                        AccountAddress.from_str("0x1"), Pagination(count=10)
                    )
                )[0]
            ),
            10,
        )

    async def test_account_module(self):
        module_abi = (
            await self.rest_client.account_module(
                AccountAddress.from_str("0x1"), "supra_coin"
            )
        )["abi"]
        self.assertEqual(module_abi["address"], "0x1")
        self.assertEqual(module_abi["name"], "supra_coin")

    async def test_account_modules(self):
        self.assertGreater(
            len(
                (
                    await self.rest_client.account_modules(
                        AccountAddress.from_str("0x1")
                    )
                )[0]
            ),
            1,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_modules(
                        AccountAddress.from_str("0x1"), Pagination(count=10)
                    )
                )[0]
            ),
            10,
        )

    async def test_account_transactions(self):
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(self.test_account.address())
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(self.test_account.address())
            ),
            2,
        )
        self.assertEqual(
            len(
                await self.rest_client.account_transactions(
                    self.test_account.address(), PaginationWithOrder(count=1)
                )
            ),
            1,
        )

    async def test_account_coin_transactions(self):
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            0,
        )
        await self.faucet_client.faucet(self.test_account.address())
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            1,
        )
        await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address()
                    )
                )[0]
            ),
            2,
        )
        self.assertEqual(
            len(
                (
                    await self.rest_client.account_coin_transactions(
                        self.test_account.address(), PaginationWithOrder(count=1)
                    )
                )[0]
            ),
            1,
        )

    async def test_transaction_by_hash(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 100
        )
        self.assertEqual(
            (await self.rest_client.transaction_by_hash(tx_hash))["hash"], tx_hash
        )

    async def test_estimate_gas_price(self):
        self.assertListEqual(
            list((await self.rest_client.estimate_gas_price()).keys()),
            ["mean_gas_price", "max_gas_price", "median_gas_price"],
        )

    async def test_transaction_parameters(self):
        self.assertListEqual(
            list((await self.rest_client.transaction_parameters()).keys()),
            ["max_transaction_time_to_live_seconds"],
        )

    async def test_submit_transaction(self):
        await self.faucet_client.faucet(self.test_account.address())
        signed_transaction_payload = await self.create_test_signed_transaction_payload()
        tx_hash = await self.rest_client.submit_transaction(signed_transaction_payload)
        self.assertEqual(
            (await self.rest_client.transaction_by_hash(tx_hash))["hash"], tx_hash
        )

    async def test_simulate_transaction(self):
        await self.faucet_client.faucet(self.test_account.address())
        signed_transaction_payload = await self.create_test_signed_transaction_payload()
        self.assertEqual(
            (await self.rest_client.simulate_transaction(signed_transaction_payload))[
                "status"
            ],
            "Success",
        )

    async def test_view(self):
        self.assertEqual(
            len(
                await self.rest_client.view("0x1::timestamp::now_microseconds", [], [])
            ),
            1,
        )

    async def test_get_table_item(self):
        response = await self.rest_client.get_table_item(
            "0x9115cf36a1bc37ccc0e3d1ceadcb72adddc65b19021dbd0623c06ce039e74fc1",
            "address",
            "u128",
            "0x46ee43b58627dff22544be91ddce928242ede01f52a281da8b372813a683abd6",
        )
        self.assertGreater(
            int(cast(str, response)),
            1,
        )

    async def test_events_by_type(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 1
        )
        self.assertGreater(
            len((await self.rest_client.events_by_type("0x1::coin::DepositEvent"))[0]),
            1,
        )
        block_height = (await self.rest_client.transaction_by_hash(tx_hash))[
            "block_header"
        ]["height"]
        self.assertEqual(
            len(
                (
                    await self.rest_client.events_by_type(
                        "0x1::coin::DepositEvent",
                        EventsPagination(
                            start_height=block_height,
                            end_height=block_height + 1,
                            limit=1,
                        ),
                    )
                )[0]
            ),
            1,
        )

    async def test_latest_block(self):
        self.assertTrue("header" in (await self.rest_client.latest_block()))

    async def test_block_by_hash(self):
        latest_block_hash = (await self.rest_client.latest_block())["header"]["hash"]
        self.assertEqual(
            (await self.rest_client.block_by_hash(latest_block_hash))["header"]["hash"],
            latest_block_hash,
        )

    async def test_block_by_height(self):
        self.assertEqual(
            (await self.rest_client.block_by_height(1))["header"]["height"], 1
        )

    async def test_txs_by_block(self):
        await self.faucet_client.faucet(self.test_account.address())
        tx_hash = await self.rest_client.transfer_supra_coin(
            self.test_account, AccountAddress.from_str("0x1"), 1
        )
        block_hash = (await self.rest_client.transaction_by_hash(tx_hash))[
            "block_header"
        ]["hash"]
        self.assertTrue(tx_hash in (await self.rest_client.txs_by_block(block_hash)))

    async def create_test_signed_transaction_payload(self) -> SignedTransaction:
        transaction_arguments = [
            TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
            TransactionArgument(1, Serializer.u64),
        ]
        transaction_payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )
        signed_transaction = await self.rest_client.create_signed_transaction(
            self.test_account, TransactionPayload(transaction_payload)
        )
        return signed_transaction

    async def asyncTearDown(self):
        await self.rest_client.close()
        await self.faucet_client.close()


class TransactionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.sender = Account.generate()

        self.rest_client = RestClient(base_url, ClientConfig(max_gas_amount=10_000))
        self.faucet_client = FaucetClient(faucet_url, self.rest_client)

        faucet_tx_hash = await self.faucet_client.faucet(self.sender.address())
        self.assertIsNotNone(faucet_tx_hash)
        await self.faucet_client.wait_for_faucet(faucet_tx_hash)

    async def asyncTearDown(self):
        await self.rest_client.close()
        await self.faucet_client.close()


class TestSupraAutomationTransactions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_url = "https://rpc-testnet.supra.com"
        self.sender = Account.generate()

        self.rest_client = RestClient(base_url, ClientConfig(max_gas_amount=10_000))
        faucet_client = FaucetClient(faucet_url, self.rest_client)

        faucet_tx_hash = await faucet_client.faucet(self.sender.address())
        self.assertIsNotNone(faucet_tx_hash)
        await faucet_client.wait_for_faucet(faucet_tx_hash)

    async def test_automation_registration(self):
        tx_hash = await self.register_test_automation_task()
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                tx_hash, "0x1::automation_registry::AutomationTaskMetaData"
            )
        )

    async def test_cancel_automation_task(self):
        task_registration_tx_hash = await self.register_test_automation_task()
        task_id = int(
            (
                await self._get_event_data_from_tx(
                    task_registration_tx_hash,
                    "0x1::automation_registry::AutomationTaskMetaData",
                )
            )["data"]["task_index"]
        )
        task_cancel_tx_hash = await self.rest_client.cancel_automation_task(
            self.sender, task_id
        )
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                task_cancel_tx_hash, "0x1::automation_registry::TaskCancelled"
            )
        )

    async def test_stop_automation_task(self):
        task_registration_tx_hash = await self.register_test_automation_task()
        task_id = int(
            (
                await self._get_event_data_from_tx(
                    task_registration_tx_hash,
                    "0x1::automation_registry::AutomationTaskMetaData",
                )
            )["data"]["task_index"]
        )
        task_stop_tx_hash = await self.rest_client.stop_automation_tasks(
            self.sender, [task_id]
        )
        self.assertIsNotNone(
            await self._get_event_data_from_tx(
                task_stop_tx_hash, "0x1::automation_registry::TasksStopped"
            )
        )

    async def register_test_automation_task(self) -> str:
        automated_function = EntryFunction.natural(
            "0x1::supra_account",
            "transfer",
            [],
            [
                TransactionArgument(AccountAddress.from_str("0x1"), Serializer.struct),
                TransactionArgument(1, Serializer.u64),
            ],
        )
        tx_hash = await self.rest_client.register_automation_task(
            self.sender,
            automated_function,
            9,
            100,
            4 * (10**8),
            int(time.time()) + 7200,
            [],
        )
        return tx_hash

    async def _get_event_data_from_tx(
        self, tx_hash: str, event_type: str
    ) -> Optional[Dict[str, Any]]:
        tx_data = await self.rest_client.transaction_by_hash(tx_hash)
        for event in tx_data["output"]["Move"]["events"]:
            if event["type"] == event_type:
                return event
        return None

    async def asyncTearDown(self):
        await self.rest_client.close()


class TestFaucetClient(unittest.IsolatedAsyncioTestCase):
    async def test_faucet(self):
        base_url = "https://rpc-testnet.supra.com"
        faucet_receiver_1 = Account.generate().address()
        faucet_receiver_2 = Account.generate().address()
        faucet_client = FaucetClient(base_url, RestClient(base_url))
        self.assertEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_1),
            0,
        )
        await faucet_client.faucet(faucet_receiver_1)
        self.assertGreater(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_1),
            0,
        )

        self.assertEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_2),
            0,
        )
        faucet_tx_hash = await faucet_client.faucet(
            faucet_receiver_2, wait_for_faucet=False
        )
        self.assertIsNotNone(faucet_tx_hash)
        faucet_tx_data = await faucet_client.wait_for_faucet(faucet_tx_hash)
        self.assertEqual(faucet_tx_data["status"], "Success")
        self.assertNotEqual(
            await faucet_client.rest_client.account_supra_balance(faucet_receiver_2),
            0,
        )
        await faucet_client.close()
