# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
import python_graphql_client

from .account import Account
from .account_address import AccountAddress
from .api_types import (
    AccountAutomatedTxPagination,
    AccountCoinTxPaginationWithOrder,
    AccountPublishedListPagination,
    AccountTxPaginationWithOrder,
    ConsensusBlockByHeightQuery,
    EventQuery,
    SupraRestAcceptType,
    TableItemRequest,
    TransactionType,
)
from .authenticator import Authenticator, MultiAgentAuthenticator
from .bcs import Serializer
from .metadata import Metadata
from .transactions import (
    EntryFunction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import StructTag, TypeTag

U64_MAX = 18446744073709551615


@dataclass
class ClientConfig:
    """
    Holds configuration options for REST API clients.

    Attributes:
        expiration_ttl (int): Time-to-live in seconds before a transaction expires.
        gas_unit_price (int): Price per unit of gas.
        max_gas_amount (int): Maximum gas units allowed for transactions.
        transaction_wait_in_seconds (int): Time to wait for transaction confirmation.
        http2 (bool): Whether to use HTTP/2 for requests.
        api_key (Optional[str]): Optional API key for authentication.
    """

    expiration_ttl: int = 600
    gas_unit_price: int = 100
    max_gas_amount: int = 100_000
    transaction_wait_in_seconds: int = 20
    http2: bool = False
    api_key: Optional[str] = None


class IndexerClient:
    """A wrapper around the Aptos Indexer Service on Hasura"""

    client: python_graphql_client.GraphqlClient

    def __init__(self, indexer_url: str, bearer_token: Optional[str] = None):
        """
        Initializes the IndexerClient.

        Args:
            indexer_url (str): GraphQL endpoint URL.
            bearer_token (Optional[str]): Optional token for Authorization header.
        """

        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = python_graphql_client.GraphqlClient(
            endpoint=indexer_url, headers=headers
        )

    async def query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a GraphQL query asynchronously.

        Args:
            query (str): The GraphQL query string.
            variables (Dict[str, Any]): Dictionary of query variables.

        Returns:
            Dict[str, Any]: The query response data.
        """

        return await self.client.execute_async(query, variables)


class RestClient:
    """A wrapper around the Aptos-core Rest API"""

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
        headers = {Metadata.APTOS_HEADER: Metadata.get_aptos_header_val()}
        self.client = httpx.AsyncClient(
            http2=client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=headers,
        )
        self.client_config = client_config
        self._chain_id = None
        if client_config.api_key:
            self.client.headers["Authorization"] = f"Bearer {client_config.api_key}"

    async def close(self):
        """
        Closes the HTTP client session.
        """

        await self.client.aclose()

    async def chain_id(self):
        """
        Fetches and caches the chain ID.

        Returns:
            int: The chain ID.
        """

        if not self._chain_id:
            info = await self.info()
            self._chain_id = int(info["chain_id"])
        return self._chain_id

    ###########
    # ACCOUNT #
    ###########

    async def account(
        self,
        account_address: AccountAddress,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, str]:
        """
        Fetches basic account information.

        Args:
            account_address (AccountAddress): Address of the account.
            accept_type (SupraRestAcceptType): MIME type to accept in response.

        Returns:
            Dict[str, str]: The account metadata.
        """

        endpoint = f"rpc/v3/accounts/{account_address}"
        headers = {"Accept": accept_type.value}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)

        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def account_transaction(
        self,
        account_address: AccountAddress,
        pagination_with_order: Optional[AccountTxPaginationWithOrder] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches transactions associated with a given account.

        Args:
            account_address (AccountAddress): The account whose transactions to fetch.
            pagination_with_order (Optional[AccountTxPaginationWithOrder]): Pagination options.
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing account transactions.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(
            accept_type.value,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        endpoint = f"rpc/v3/accounts/{account_address}/transactions"
        headers = {"Accept": accept_type.value}
        params = pagination_with_order.to_params() if pagination_with_order else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def account_automated_transactions(
        self,
        address: AccountAddress,
        pagination: Optional[AccountAutomatedTxPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
        # TODO: Add return type
    ):
        """
        Fetches automated transactions for a given account.

        Args:
            address (AccountAddress): The account address.
            pagination (Optional[AccountAutomatedTxPagination]): Pagination options.
            accept_type (str): Desired content type of the response.

        Returns:
            Tuple[Dict[str, Any], str]: A tuple containing:
                - JSON response with transactions.
                - Cursor for fetching the next page.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(
            accept_type.value,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        endpoint = f"rpc/v3/accounts/{address}/automated_transactions"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        data = resp.json()
        # TODO: need to extract Txn data form `data`
        resp_cursor = resp.headers.get("x-supra-cursor", "")

        return data, resp_cursor

    async def coin_transaction(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountCoinTxPaginationWithOrder] = None,
        # txn_type: None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches coin-specific transactions for a given account.

        Args:
            account_address (AccountAddress): The account address.
            pagination (Optional[AccountCoinTxPaginationWithOrder]): Pagination options.
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing coin transactions.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(
            accept_type.value,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/coin_transactions"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches the full list of resources associated with an account.

        Args:
            account_address (AccountAddress): The account address.
            pagination (Optional[AccountPublishedListPagination]): Pagination options.
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing account resources.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(
            accept_type.value,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/resources"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches the Move modules published under a given account.

        Args:
            account_address (AccountAddress): The account address.
            pagination (Optional[AccountPublishedListPagination]): Pagination options.
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing the list of modules.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(
            accept_type.value,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/modules"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def account_specific_resource(
        self,
        path_param: Tuple[AccountAddress, str],
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches a specific resource from an account.

        Args:
            path_param (Tuple[AccountAddress, str]): A tuple of (address, resource_struct_tag).
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing the specific resource.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(accept_type.value, [SupraRestAcceptType.OCTET.value])
        address, tag_string = path_param[0], path_param[1]
        endpoint = f"rpc/v3/accounts/{address}/resources/{tag_string}"
        headers = {"Accept": accept_type.value}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {address}", resp.status)
        return resp.json()

    async def account_specific_modules(
        self,
        path_param: Tuple[AccountAddress, str],
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches a specific module from an account.

        Args:
            path_param (Tuple[AccountAddress, str]): A tuple of (address, module_name).
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing the specific module.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(accept_type.value, [SupraRestAcceptType.OCTET.value])
        address, module_name = path_param[0], path_param[1]
        endpoint = f"rpc/v3/accounts/{address}/modules/{module_name}"
        headers = {"Accept": accept_type.value}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {address}", resp.status)
        return resp.json()

    ################
    # TRANSACTIONS #
    ################
    async def estimate_gas_price(self) -> Dict[str, Any]:
        """
        Estimates the current gas price based on recent network conditions.

        Returns:
            Dict[str, Any]: JSON response with gas price estimation.

        Raises:
            ApiError: If the API request fails with a status code >= 400.
        """

        endpoint = "rpc/v2/transactions/estimate_gas_price"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status)
        return resp.json()

    async def transaction_parameters(self) -> Dict[str, Any]:
        """
        Fetches the current network transaction configuration parameters.

        Returns:
            Dict[str, Any]: JSON response with transaction parameter settings.

        Raises:
            ApiError: If the API request fails with a status code >= 400.
        """

        endpoint = "rpc/v1/transactions/parameters"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status)
        return resp.json()

    async def transaction_by_hash(self, hash: str) -> Dict[str, Any]:
        """
        Fetches a transaction by its hash.

        Args:
            hash (str): The hash of the transaction.

        Returns:
            Dict[str, Any]: JSON response containing transaction details.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = f"rpc/v3/transactions/{hash}"

        resp = await self._get(endpoint=endpoint)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {hash}", resp.status)
        return resp.json()

    async def submit_txn(
        self, transaction_data: Union[Dict[str, Any], bytes]
    ) -> Dict[str, Any]:
        """
        Submits a signed transaction for execution.

        Args:
            transaction_data (Union[Dict[str, Any], bytes]): The transaction payload.

        Returns:
            Dict[str, Any]: JSON response from the API.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/transactions/submit"

        resp = await self._post(endpoint=endpoint, data=transaction_data)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status)
        return resp.json()

    async def simulate_tx(
        self, transaction_data: Union[Dict[str, Any], bytes]
    ) -> Dict[str, Any]:
        """
        Simulates a transaction without submitting it to the chain.

        Args:
            transaction_data (Union[Dict[str, Any], bytes]): The transaction payload.

        Returns:
            Dict[str, Any]: JSON simulation result.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/transactions/simulate"

        resp = await self._post(endpoint=endpoint, data=transaction_data)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status)
        return resp.json()

    async def simulate_bcs_transaction(
        self,
        signed_transaction: SignedTransaction,
        estimate_gas_usage: bool = False,
    ) -> Dict[str, Any]:
        """
        NOT PRESENT IN SUPRA
        """
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        params = {}
        if estimate_gas_usage:
            params = {
                "estimate_gas_unit_price": "true",
                "estimate_max_gas_amount": "true",
            }

        response = await self.client.post(
            f"{self.base_url}/transactions/simulate",
            params=params,
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(response.text, response.status_code)

        return response.json()

    async def submit_bcs_transaction(
        self, signed_transaction: SignedTransaction
    ) -> str:
        """
        NOT PRESENT IN SUPRA
        """

        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        response = await self.client.post(
            f"{self.base_url}/transactions",
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]

    async def submit_and_wait_for_bcs_transaction(
        self, signed_transaction: SignedTransaction
    ) -> Dict[str, Any]:
        """
        NOT PRESENT IN SUPRA
        """

        txn_hash = await self.submit_bcs_transaction(signed_transaction)
        await self.wait_for_transaction(txn_hash)
        return await self.transaction_by_hash(txn_hash)

    async def transaction_pending(self, txn_hash: str) -> bool:
        """
        NOT PRESENT IN SUPRA
        """

        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        # TODO(@davidiw): consider raising a different error here, since this is an ambiguous state
        if response.status_code == HTTPStatus.NOT_FOUND:
            return True
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(response.text, response.status_code)
        return response.json()["type"] == "pending_transaction"

    async def wait_for_transaction(self, txn_hash: str) -> None:
        """
        NOT PRESENT IN SUPRA
        """

        """
        Waits up to the duration specified in client_config for a transaction to move past pending
        state.
        """

        count = 0
        while await self.transaction_pending(txn_hash):
            assert count < self.client_config.transaction_wait_in_seconds, (
                f"transaction {txn_hash} timed out"
            )
            await asyncio.sleep(1)
            count += 1

        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        assert "success" in response.json() and response.json()["success"], (
            f"{response.text} - {txn_hash}"
        )

    async def account_transaction_sequence_number_status(
        self, address: AccountAddress, sequence_number: int
    ) -> bool:
        """
        NOT PRESENT IN SUPRA
        """

        """Retrieve the state of a transaction by account and sequence number."""
        response = await self._get(
            endpoint=f"accounts/{address}/transactions",
            params={
                "limit": 1,
                "start": sequence_number,
            },
        )
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(response.text, response.status_code)
        data = response.json()
        return len(data) == 1 and data[0]["type"] != "pending_transaction"

    ########################
    # TRANSACTIONS HELPERS #
    ########################

    async def create_multi_agent_bcs_transaction(
        self,
        sender: Account,
        secondary_accounts: List[Account],
        payload: TransactionPayload,
    ) -> SignedTransaction:
        """
        NOT PRESENT IN SUPRA
        """

        raw_transaction = MultiAgentRawTransaction(
            RawTransaction(
                sender.address(),
                await self.account_sequence_number(sender.address()),
                payload,
                self.client_config.max_gas_amount,
                self.client_config.gas_unit_price,
                int(time.time()) + self.client_config.expiration_ttl,
                await self.chain_id(),
            ),
            [x.address() for x in secondary_accounts],
        )

        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender.sign_transaction(raw_transaction),
                [
                    (
                        x.address(),
                        x.sign_transaction(raw_transaction),
                    )
                    for x in secondary_accounts
                ],
            )
        )

        return SignedTransaction(raw_transaction.inner(), authenticator)

    async def create_bcs_transaction(
        self,
        sender: Account | AccountAddress,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> RawTransaction:
        """
        NOT PRESENT IN SUPRA
        """

        if isinstance(sender, Account):
            sender_address = sender.address()
        else:
            sender_address = sender

        sequence_number = (
            sequence_number
            if sequence_number is not None
            else await self.account_sequence_number(sender_address)
        )
        return RawTransaction(
            sender_address,
            sequence_number,
            payload,
            self.client_config.max_gas_amount,
            self.client_config.gas_unit_price,
            int(time.time()) + self.client_config.expiration_ttl,
            await self.chain_id(),
        )

    async def create_bcs_signed_transaction(
        self,
        sender: Account,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> SignedTransaction:
        """
        NOT PRESENT IN SUPRA
        """

        raw_transaction = await self.create_bcs_transaction(
            sender, payload, sequence_number
        )
        authenticator = sender.sign_transaction(raw_transaction)
        return SignedTransaction(raw_transaction, authenticator)

    #########################
    # TRANSACTIONS WRAPPERS #
    #########################

    async def register_automation_task(
        self,
        sender: Account,
        task_payload: EntryFunction,
        task_max_gas_amount: int,
        task_gas_price_cap: int,
        task_expiry_time_secs: int,
        task_automation_fee_cap: int,
        simulate: bool = False,
        sequence_number: Optional[int] = None,
    ) -> Union[Dict[str, Any], str]:
        """
        Registers a new automation task with the automation registry.

        This method mirrors the Rust implementation that creates AutomationRegistration
        with RegistrationParams. Follows the same pattern as cancel_automation_task for consistency.

        Args:
            sender (Account): The account that will sign and send the transaction
            task_payload (EntryFunction): The entry function to be executed automatically
            task_max_gas_amount (int): Maximum gas amount to be paid when registered task is executed
            task_gas_price_cap (int): Maximum gas price user is willing to pay for the task
            task_expiry_time_secs (int): Task expire time in seconds since EPOCH
            task_automation_fee_cap (int): The maximum automation fee per epoch user is willing to pay
            simulate (bool): Whether to simulate the transaction instead of executing it
            sequence_number (Optional[int]): Optional sequence number override

        Returns:
            str: Transaction hash if executed, or simulation result if simulated

        Raises:
            ApiError: If the API request fails
        """

        transaction_arguments = [
            TransactionArgument(
                task_payload, Serializer.struct
            ),  # The task payload (EntryFunction)
            TransactionArgument(task_expiry_time_secs, Serializer.u64),
            TransactionArgument(task_max_gas_amount, Serializer.u64),
            TransactionArgument(task_gas_price_cap, Serializer.u64),
            TransactionArgument(task_automation_fee_cap, Serializer.u64),
            TransactionArgument(
                [], Serializer.sequence
            ),  # auxiliary_data (empty vector)
        ]

        # Create the payload for the automation registry register function
        # Based on: TransactionPayload::AutomationRegistration(registration_params) from Rust
        payload = EntryFunction.natural(
            "0x1::automation_registry",  # Standard library automation registry module
            # Function name in the module (assuming this is the function name)
            "register_task",
            [],  # No type arguments needed
            transaction_arguments,  # The registration parameters
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )

        if simulate:
            return await self.simulate_bcs_transaction(signed_transaction, True)
        else:
            return await self.submit_bcs_transaction(signed_transaction)

    async def cancel_automation_task(
        self,
        sender: Account,
        task_index: int,
        simulate: bool = False,
        sequence_number: Optional[int] = None,
    ) -> Union[Dict[str, Any], str]:
        """
        Cancels an automation task by calling the automation registry.

        This method mirrors the Rust implementation that calls automation_registry_cancel_task.
        Follows the same pattern as bcs_transfer for consistency.

        Args:
            sender (Account): The account that will sign and send the transaction
            task_index (int): The ID of the automation task to cancel
            simulate (bool): Whether to simulate the transaction instead of executing it
            sequence_number (Optional[int]): Optional sequence number override

        Returns:
            str: Transaction hash if executed, or simulation result if simulated

        Raises:
            ApiError: If the API request fails
        """

        # Build the transaction arguments - task_index as u64
        transaction_arguments = [
            TransactionArgument(task_index, Serializer.u64),
        ]

        # Create the payload for the automation registry cancel_task function
        # Based on: automation_registry_cancel_task(task_index) from Rust
        payload = EntryFunction.natural(
            "0x1::automation_registry",  # Standard library automation registry module
            "cancel_task",  # Function name in the module
            [],  # No type arguments needed
            transaction_arguments,  # The task_index argument
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )

        if simulate:
            return await self.simulate_bcs_transaction(signed_transaction, True)
        else:
            return await self.submit_bcs_transaction(signed_transaction)

    async def stop_automation_tasks(
        self,
        sender: Account,
        task_indexes: List[int],
        simulate: bool = False,
        sequence_number: Optional[int] = None,
    ) -> Union[Dict[str, Any], str]:
        """
        Stop/Immediately cancel registered automation tasks by indexes.

        This method mirrors the Rust implementation that calls automation_registry_stop_tasks.
        Follows the same pattern as cancel_automation_task for consistency.

        Args:
            sender (Account): The account that will sign and send the transaction
            task_indexes (List[int]): List of task IDs to stop immediately
            simulate (bool): Whether to simulate the transaction instead of executing it
            sequence_number (Optional[int]): Optional sequence number override

        Returns:
            str: Transaction hash if executed, or simulation result if simulated

        Raises:
            ApiError: If the API request fails
        """

        transaction_arguments = [
            TransactionArgument(task_indexes, Serializer.sequence),
        ]

        # Create the payload for the automation registry stop_tasks function
        # Based on: automation_registry_stop_tasks(task_indexes) from Rust
        payload = EntryFunction.natural(
            "0x1::automation_registry",  # Standard library automation registry module
            "stop_tasks",  # Function name in the module
            [],  # No type arguments needed
            transaction_arguments,  # The task_indexes argument (vector<u64>)
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )

        if simulate:
            return await self.simulate_bcs_transaction(signed_transaction, True)
        else:
            return await self.submit_bcs_transaction(signed_transaction)

    # :!:>bcs_transfer
    async def bcs_transfer(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        NOT PRESENT IN SUPRA
        """

        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        # <:!:bcs_transfer
        return await self.submit_bcs_transaction(signed_transaction)

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        NOT PRESENT IN SUPRA
        """

        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer_coins",
            [TypeTag(StructTag.from_str(coin_type))],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_transaction(signed_transaction)

    async def transfer_object(
        self, owner: Account, object: AccountAddress, to: AccountAddress
    ) -> str:
        """
        NOT PRESENT IN SUPRA
        """

        transaction_arguments = [
            TransactionArgument(object, Serializer.struct),
            TransactionArgument(to, Serializer.struct),
        ]

        payload = EntryFunction.natural(
            "0x1::object",
            "transfer_call",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            owner,
            TransactionPayload(payload),
        )
        return await self.submit_bcs_transaction(signed_transaction)

    ##########
    # BLOCKS #
    ##########
    async def latest_block(self) -> Dict[str, Any]:
        """
        Fetches the latest block from the blockchain.

        Returns:
            Dict[str, Any]: JSON response containing latest block information.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/block"

        resp = await self._get(endpoint=endpoint)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - NIL", resp.status)
        return resp.json()

    async def block_info_by_hash(self, block_hash: str) -> Dict[str, Any]:
        """
        Fetches block information using a block hash.

        Args:
            block_hash (str): The hash of the block.

        Returns:
            Dict[str, Any]: JSON response containing block info.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = f"rpc/v3/block/{block_hash}"

        resp = await self._get(endpoint=endpoint)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status)
        return resp.json()

    async def block_by_height(
        self,
        height: int,
        transaction_type: Optional[TransactionType] = None,
        with_finalized_transaction: bool = False,
    ) -> Dict[str, Any]:
        """
        Fetches block data by height with optional transaction filtering.

        Args:
            height (int): The height of the block.
            transaction_type (Optional[TransactionType]): Filter transactions by type.
            with_finalized_transaction (bool): Whether to include finalized transactions.

        Returns:
            Dict[str, Any]: JSON response with block data.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = f"rpc/v3/block/height/{height}"

        params = {"with_finalized_transactions": with_finalized_transaction}

        if transaction_type is not None:
            params["transaction_type"] = transaction_type.value

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {height}", resp.status)
        return resp.json()

    async def txs_by_block(
        self, block_hash: str, transaction_type: Optional[TransactionType] = None
    ) -> Dict[str, Any]:
        """
        Fetches transactions for a given block hash.

        Args:
            block_hash (str): The hash of the block.
            transaction_type (Optional[TransactionType]): Filter transactions by type.

        Returns:
            Dict[str, Any]: JSON response with transactions in the block.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = f"rpc/v3/block/{block_hash}/transactions"

        params = {}
        if transaction_type is not None:
            params["transaction_type"] = transaction_type.value

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status)
        return resp.json()

    async def latest_consensus_block(
        self, with_batches: Optional[ConsensusBlockByHeightQuery] = None
    ) -> Dict[str, Any]:
        """
        Fetches the latest consensus block from the chain.

        Args:
            with_batches (Optional[ConsensusBlockByHeightQuery]):
                Optional query parameters to include batched transactions or metadata.

        Returns:
            Dict[str, Any]: JSON response containing the latest consensus block data.

        Raises:
            ApiError: If the API request fails with a status code >= 400.
        """

        endpoint = "rpc/v2/consensus/block"
        params = with_batches.to_params() if with_batches is not None else {}

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status)
        return resp.json()

    async def consensus_block(
        self, height: int, with_batches: Optional[ConsensusBlockByHeightQuery] = None
    ) -> Dict[str, Any]:
        """
        Fetches a consensus block by its height with optional batched data.

        Args:
            height (int): The height of the consensus block to retrieve.
            with_batched (Optional[ConsensusBlockByHeightQuery]):
                Optional query parameters for including batched transactions or metadata.

        Returns:
            Dict[str, Any]: JSON response containing the consensus block data.

        Raises:
            ApiError: If the API request fails with a status code >= 400.
        """

        endpoint = f"rpc/v2/consensus/height/{height}"
        params = with_batches.to_params() if with_batches is not None else {}

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text} - height: {height}", resp.status)
        return resp.json()

    async def committee_authorization(self, epoch: int) -> Dict[str, Any]:
        endpoint = f"rpc/v1/consensus/committee_authorization/{epoch}"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text} - epoch: {epoch}", resp.status)
        return resp.json()

    ##########
    # TABLES #
    ##########
    async def table_items_by_key(
        self,
        table_handle: AccountAddress,
        table_item_request: Optional[TableItemRequest] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve an item from a table by key.

        Args:
            table_handle (AccountAddress): Table handle to lookup. Should be retrieved using account resources API.
            table_item_request (TableItemRequest): Request containing item key and value types and item key itself.

        Returns:
            Dict[str, Any]: Item of the table as MoveValueApi.
        """

        endpoint = f"rpc/v2/tables/{table_handle}/item"
        content = (
            table_item_request.to_params() if table_item_request is not None else {}
        )

        resp = await self._post(
            endpoint=endpoint,
            data=content,
            headers={"content-type": "application/json"},
        )

        if resp.status >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text} - table_handle: {table_handle}", resp.status)
        return resp.json()

    ########
    # VIEW #
    ########

    async def view_function(self, data: Union[Dict[str, Any], bytes]) -> Dict[str, Any]:
        """
        Executes a view function without creating a transaction on-chain.

        Args:
            data (Union[Dict[str, Any], bytes]): The request payload for the view function.

        Returns:
            Dict[str, Any]: JSON result of the view function.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/view"

        resp = await self._post(endpoint=endpoint, data=data)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {data}", resp.status)
        return resp.json()

    ##########
    # EVENTS #
    ##########

    async def events_by_type(
        self, event_type: str, query: Optional[EventQuery] = None
    ) -> Dict[str, Any]:
        """
        Fetches events of a specific type.

        Args:
            event_type (str): Type of event to fetch.
            query (Optional[EventQuery]): Optional query parameters for filtering/pagination.

        Returns:
            Dict[str, Any]: JSON response containing event data.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = f"rpc/v3/events/{event_type}"

        params = query.to_params() if query is not None else {}

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {event_type} || {query}", resp.status)
        return resp.json()

    ##########
    # WALLET #
    ##########

    async def faucet(self, address: AccountAddress) -> Dict[str, Any]:
        """
        Requests faucet funds to be sent to the given account address.

        Args:
            address (AccountAddress): The target account address to receive funds.

        Returns:
            Dict[str, Any]: JSON response containing the faucet transaction information.

        Raises:
            ApiError: If the API request fails with a non-200 status code.
        """

        endpoint = f"rpc/v1/wallet/faucet/{address}"

        resp = await self._get(endpoint=endpoint)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - account_address: {address}", resp.status)
        return resp.json()

    async def faucet_transaction_by_hash(self, hash: str) -> Dict[str, Any]:
        """
        Retrieves details of a faucet transaction by its hash.

        Args:
            hash (str): The hash of the faucet transaction.

        Returns:
            Dict[str, Any]: JSON response containing transaction details.

        Raises:
            ApiError: If the API request fails with a non-200 status code.
        """

        endpoint = f"rpc/v2/wallet/faucet/transactions/{hash}"

        resp = await self._get(endpoint=endpoint)
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - hash: {hash}", resp.status)
        return resp.json()

    ###########
    # HELPERS #
    ###########

    async def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], bytes]] = None,
    ) -> httpx.Response:
        """
        Performs an asynchronous POST request.

        Args:
            endpoint (str): API endpoint.
            params (Optional[Dict[str, Any]]): Query parameters.
            headers (Optional[Dict[str, Any]]): Request headers.
            data (Optional[Union[Dict[str, Any], bytes]]): POST body data.

        Returns:
            httpx.Response: The response from the server.
        """

        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}

        headers = headers or {}
        if isinstance(data, bytes):
            headers["content-type"] = "application/x.supra.signed_transaction.bcs"
            return await self.client.post(
                url=f"{self.base_url}/{endpoint}",
                params=params,
                headers=headers,
                content=data,
            )
        else:
            # JSON params / None
            return await self.client.post(
                url=f"{self.base_url}/{endpoint}",
                params=params,
                headers=headers,
                json=data,
            )

    async def _get(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """
        Performs an asynchronous GET request.

        Args:
            endpoint (str): Endpoint to call.
            headers (Optional[Dict[str, str]]): Optional headers.
            params (Optional[Dict[str, Any]]): Optional query parameters.

        Returns:
            httpx.Response: The response from the server.
        """

        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}
        return await self.client.get(
            url=f"{self.base_url}/{endpoint}", params=params, headers=headers
        )

    def _check_accept_type(self, accept_type: str, unsupported: List[str]) -> None:
        """
        Checks if the given Accept type is supported.

        Args:
            accept_type (str): The content-type requested.
            unsupported (List[str]): List of unsupported types.

        Raises:
            AcceptTypeNotSupported: If `accept_type` is not supported.
        """

        if accept_type in unsupported:
            supported = [
                t
                for t in [e.value for e in SupraRestAcceptType]
                if t not in unsupported
            ]
            raise AcceptTypeNotSupported(accept_type, supported)


class FaucetClient:
    """Faucet creates and funds accounts. This is a thin wrapper around that."""

    base_url: str
    rest_client: RestClient
    headers: Dict[str, str]

    def __init__(
        self, base_url: str, rest_client: RestClient, auth_token: Optional[str] = None
    ):
        """
        Initializes the FaucetClient.

        Args:
            base_url (str): Faucet service URL.
            rest_client (RestClient): Instance of RestClient to use.
            auth_token (Optional[str]): Optional bearer token for authorization.
        """

        self.base_url = base_url
        self.rest_client = rest_client
        self.headers = {}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

    async def close(self):
        await self.rest_client.close()

    async def fund_account(
        self, address: AccountAddress, amount: int, wait_for_transaction=True
    ):
        """
        Funds an account by minting coins. Creates the account if it doesn't exist.

        Args:
            address (AccountAddress): The address to fund.
            amount (int): Amount of coins to mint.
            wait_for_transaction (bool): Whether to wait for the transaction to be confirmed.

        Returns:
            str: The transaction hash.
        """

        request = f"{self.base_url}/mint?amount={amount}&address={address}"
        response = await self.rest_client.client.post(request, headers=self.headers)
        if response.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(response.text, response.status_code)
        txn_hash = response.json()[0]
        if wait_for_transaction:
            await self.rest_client.wait_for_transaction(txn_hash)
        return txn_hash

    async def healthy(self) -> bool:
        """
        Checks if the Faucet service is healthy.

        Returns:
            bool: True if healthy, False otherwise.
        """

        response = await self.rest_client.client.get(self.base_url)
        return "tap:ok" == response.text


class ApiError(Exception):
    """
    Exception raised when the API returns a non-2xx response.

    Attributes:
        status_code (int): The HTTP status code returned.
    """

    status_code: int

    def __init__(self, message: str, status_code: int):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.status_code = status_code


class AcceptTypeNotSupported(Exception):
    """
    Exception raised when an Accept header contains an unsupported MIME type.

    Attributes:
        accept_type (str): The unsupported type.
        supported_types (List[str]): List of supported types.
    """

    def __init__(self, accept_type: str, supported_types: list[str]):
        self.accept_type = accept_type
        self.supported_types = supported_types
        super().__init__(
            f"Accept type '{accept_type}' not supported. Supported types: {
                ', '.join(supported_types)
            }",
            415,
        )


class AccountNotFound(Exception):
    """
    Exception raised when a requested account cannot be found.

    Attributes:
        account (AccountAddress): The account that was not found.
    """

    account: AccountAddress

    def __init__(self, message: str, account: AccountAddress):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.account = account


class ResourceNotFound(Exception):
    """
    Exception raised when a requested resource cannot be found.

    Attributes:
        resource (str): The resource name or identifier.
    """

    resource: str

    def __init__(self, message: str, resource: str):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.resource = resource
