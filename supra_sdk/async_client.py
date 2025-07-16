# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0
import asyncio
import time
import unittest
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from supra_sdk.account import Account
from supra_sdk.account_address import AccountAddress
from supra_sdk.api_types import (
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
from supra_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    Ed25519Authenticator,
    MultiAgentAuthenticator,
)
from supra_sdk.bcs import Serializer
from supra_sdk.transactions import (
    AutomationRegistrationParamsV1,
    AutomationRegistrationParamsV1Data,
    EntryFunction,
    ModuleId,
    MoveTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    SupraTransaction,
    TransactionArgument,
    TransactionPayload,
    TransactionPayloadAutomationRegistration,
)
from supra_sdk.type_tag import StructTag, TypeTag

from .metadata import Metadata

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


class RestClient:
    """A wrapper around the Supra-core Rest API"""

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
            endpoint = "rpc/v3/transactions/chain_id"
            resp = await self._get(endpoint=endpoint)
            if resp.status_code != HTTPStatus.OK:
                raise ApiError(f"{resp.text}", resp.status_code)
            result = resp.json()
            self._chain_id = (
                int(result)
                if isinstance(result, (int, str))
                else int(result.get("chain_id", result))
            )
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

        endpoint = f"rpc/v3/accounts/{account_address.__str__()}"
        headers = {"Accept": accept_type.value}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status_code)
        return resp.json()

    async def account_balance(self, data: Union[Dict[str, Any], bytes]) -> int:
        """
        Get the account balance.

        This method calls the `view_function` to retrieve the balance of an account
        and returns it as an integer.

        Args:
            data (Union[Dict[str, Any], bytes]): The payload or raw bytes required
                by the view function to fetch the balance.

        Returns:
            int: The account balance.
        """
        res = await self.view_function(data)
        return int(res["result"][0])

    async def account_sequence_number(
        self,
        account_address: AccountAddress,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> int:
        """
        Get the sequence number for an account.

        This method retrieves the current sequence number (nonce) for the given
        account address. The sequence number is typically used to prevent
        transaction replay and ensure transaction ordering.

        Args:
            account_address (AccountAddress): The address of the account.
            accept_type (SupraRestAcceptType, optional): The accepted response
                format. Defaults to `SupraRestAcceptType.JSON`.

        Returns:
            int: The account's current sequence number.
        """
        res = await self.account(
            account_address=account_address, accept_type=accept_type
        )
        return int(res["sequence_number"])

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

        endpoint = f"rpc/v3/accounts/{account_address.__str__()}/transactions"
        headers = {"Accept": accept_type.value}
        params = pagination_with_order.to_params() if pagination_with_order else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status_code)
        return resp.json()

    async def account_automated_transactions(
        self,
        address: AccountAddress,
        pagination: Optional[AccountAutomatedTxPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
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

        endpoint = f"rpc/v3/accounts/{address.__str__()}/automated_transactions"
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
    ) -> List[Dict[str, Any]]:
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
        endpoint = f"rpc/v3/accounts/{account_address.__str__()}/coin_transactions"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status_code)
        return resp.json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> List[Dict[str, Any]]:
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
        endpoint = f"rpc/v3/accounts/{account_address.__str__()}/resources"
        headers = {"Accept": accept_type.value}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status_code)
        return resp.json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> List[Dict[str, Any]]:
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

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {account_address}", resp.status_code)
        return resp.json()

    async def account_specific_resource(
        self,
        path_param: Tuple[AccountAddress, str],
        accept_type: SupraRestAcceptType = SupraRestAcceptType.JSON,
    ) -> Dict[str, Any]:
        """
        Fetches a specific resource from an account.

        Args:
            path_param (Tuple[AccountAddress, str]): A tuple of (address, resouce_struct_tag).
            accept_type (str): Desired content type of the response.

        Returns:
            Dict[str, Any]: JSON response containing the specific resource.

        Raises:
            ApiError: If the API request fails.
        """

        self._check_accept_type(accept_type.value, [SupraRestAcceptType.OCTET.value])
        address, tag_string = path_param[0], path_param[1]
        endpoint = f"rpc/v3/accounts/{address.__str__()}/resources/{tag_string}"
        headers = {"Accept": accept_type.value}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {address}", resp.status_code)
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {address}", resp.status_code)
        return resp.json()

    async def aggregator_value(
        self,
        account_address: AccountAddress,
        resource_type: str,
        aggregator_path: List[str],
    ) -> int:
        source = await self.account_specific_resource((account_address, resource_type))
        source_data = data = source["data"]

        while len(aggregator_path) > 0:
            key = aggregator_path.pop()
            if key not in data:
                raise ApiError(
                    f"aggregator path not found in data: {source_data}", source_data
                )
            data = data[key]

        if "vec" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["vec"]
        if len(data) != 1:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data[0]
        if "aggregator" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["aggregator"]
        if "vec" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data["vec"]
        if len(data) != 1:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        data = data[0]
        if "handle" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        if "key" not in data:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        handle = data["handle"]
        key = data["key"]

        table_request = TableItemRequest(key_type="address", value_type="u128", key=key)
        return int(
            await self.table_items_by_key(
                table_handle=handle, table_item_request=table_request
            )
        )

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
        if resp.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status_code)
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
        if resp.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status_code)
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {hash}", resp.status_code)
        return resp.json()

    async def submit_txn(self, transaction_data: Dict[str, Any]) -> str:
        """
        Submits a signed transaction for execution.

        Args:
            transaction_data (Dict[str, Any]): The transaction payload.

        Returns:
            Dict[str, Any]: JSON response from the API.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/transactions/submit"
        txn_data = transaction_data.to_dict()
        resp = await self._post(endpoint=endpoint, data=txn_data)
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {txn_data}", resp.status_code)
        return resp.json()

    async def simulate_tx(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulates a transaction without submitting it to the chain.

        Args:
            transaction_data (Dict[str, Any]): The transaction payload.

        Returns:
            Dict[str, Any]: JSON simulation result.

        Raises:
            ApiError: If the API request fails.
        """

        endpoint = "rpc/v3/transactions/simulate"
        txn_data = transaction_data.to_dict()
        resp = await self._post(endpoint=endpoint, data=txn_data)
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {txn_data}", resp.status_code)
        return resp.json()

    async def simulate_bcs_txn(
        self, transaction_data: SignedTransaction | bytes
    ) -> Dict[str, Any]:
        """
        Simulate a BCS (Binary Canonical Serialization) transaction without submitting it.

        This method serializes the provided transaction if needed, then sends it to
        the simulation endpoint. This allows you to estimate gas usage or check validity
        before broadcasting the transaction.

        Args:
            transaction_data (Union[SignedTransaction, bytes]): The signed transaction
                object or raw BCS bytes to simulate.

        Returns:
            Dict[str, Any]: The simulation result returned by the Supra node.
        """

        headers = {"Content-Type": "application/x.supra.signed_transaction+bcs"}
        endpoint = "rpc/v3/transactions/simulate"

        if isinstance(transaction_data, SignedTransaction):
            supra_txn = SupraTransaction.create_move_transaction(transaction_data)
            supra_serializer = Serializer()
            supra_txn.serialize(supra_serializer)
            transaction_data = supra_serializer.output()

        resp = await self._post(
            endpoint=endpoint, data=transaction_data, headers=headers
        )
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status_code)
        return resp.json()

    async def submit_bcs_txn(self, transaction_data: SignedTransaction | bytes) -> str:
        """
        Submit a signed BCS transaction to the network.

        This method serializes the transaction if needed, sends it to the submit
        endpoint, and returns the transaction hash.

        Args:
            transaction_data (Union[SignedTransaction, bytes]): The signed transaction
                object or raw BCS bytes to submit.

        Returns:
            str: The transaction hash of the submitted transaction.
        """

        endpoint = "rpc/v3/transactions/submit"
        headers = {"Content-Type": "application/x.supra.signed_transaction+bcs"}

        if isinstance(transaction_data, SignedTransaction):
            supra_txn = SupraTransaction.create_move_transaction(transaction_data)
            supra_serializer = Serializer()
            supra_txn.serialize(supra_serializer)
            transaction_data = supra_serializer.output()

        resp = await self._post(
            endpoint=endpoint, data=transaction_data, headers=headers
        )

        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status_code)
        return resp.json()

    async def submit_and_wait_for_bcs_transaction(
        self, signed_transaction: bytes
    ) -> Dict[str, Any]:
        """
        Submit a signed BCS transaction and wait for its final confirmation.

        This method submits the transaction, waits until it moves out of the pending
        state, and returns the finalized transaction details.

        Args:
            signed_transaction (bytes): The raw BCS-encoded signed transaction.

        Returns:
            Dict[str, Any]: The confirmed transaction details.
        """

        txn_hash = await self.submit_bcs_txn(signed_transaction)
        await self.wait_for_transaction(txn_hash)
        return await self.transaction_by_hash(txn_hash)

    async def transaction_pending(self, txn_hash: str) -> bool:
        """
        Check if a transaction is still pending.

        This method queries the transaction by its hash and determines if it's
        still in the pending state.

        Args:
            txn_hash (str): The hash of the transaction to check.

        Returns:
            bool: True if the transaction is pending or not found yet; False otherwise.
        """

        try:
            response = await self.transaction_by_hash(txn_hash)
            return response.get("type") == "pending_transaction"

        except ApiError as e:
            if e.status_code == HTTPStatus.NOT_FOUND:
                return True  # Transaction not found yet, keep waiting
            else:
                raise e

    async def wait_for_transaction(self, txn_hash: str) -> None:
        """
        Wait for a transaction to complete or fail.

        This method repeatedly checks the transaction status until it is no longer
        pending or until the configured timeout is reached.

        Args:
            txn_hash (str): The hash of the transaction to wait for.

        Raises:
            AssertionError: If the transaction times out or fails with a non-success status.
        """

        count = 0
        while await self.transaction_pending(txn_hash):
            assert count < self.client_config.transaction_wait_in_seconds, (
                f"transaction {txn_hash} timed out"
            )
            await asyncio.sleep(1)
            count += 1

        # Get final transaction data
        txn_data = await self.transaction_by_hash(txn_hash)

        assert txn_data.get("status") == "Success", f"Transaction failed with status: {
            txn_data.get('status')
        } - {txn_hash}"

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
        Create a multi-agent BCS signed transaction.

        This method builds and signs a multi-agent transaction, where the main sender
        and one or more secondary accounts sign the same raw transaction.

        Args:
            sender (Account): The primary account sending the transaction.
            secondary_accounts (List[Account]): The secondary accounts that must also
                authorize the transaction.
            payload (TransactionPayload): The transaction payload to execute.

        Returns:
            SignedTransaction: The signed multi-agent BCS transaction.
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
        Create an unsigned BCS raw transaction.

        This method builds a raw transaction with the provided sender, payload, and
        optionally a custom sequence number.

        Args:
            sender (Union[Account, AccountAddress]): The account object or its address.
            payload (TransactionPayload): The payload describing the action to perform.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

        Returns:
            RawTransaction: The constructed raw transaction.
        """

        # Extract sender address
        sender_address = sender.address() if isinstance(sender, Account) else sender

        # Get sequence number if not provided
        if sequence_number is None:
            account_info = await self.account(sender_address)
            sequence_number = account_info["sequence_number"]

        # Get chain ID
        chain_id = await self.chain_id()

        return RawTransaction(
            sender=sender_address,
            sequence_number=sequence_number,
            payload=payload,
            max_gas_amount=self.client_config.max_gas_amount,
            gas_unit_price=self.client_config.gas_unit_price,
            expiration_timestamps_secs=int(time.time())
            + self.client_config.expiration_ttl,
            chain_id=chain_id,
        )

    async def create_bcs_signed_transaction(
        self,
        sender: Account,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> SignedTransaction:
        """
        Create a BCS signed transaction and serialize it.

        This method builds a raw transaction, signs it using the sender's key, wraps it
        in an authenticator, and serializes it to BCS format ready for submission.

        Args:
            sender (Account): The account signing the transaction.
            payload (TransactionPayload): The transaction payload.
            sequence_number (Optional[int], optional): The sequence number to use.
                If not provided, the current sequence number will be fetched.

        Returns:
            bytes: The serialized BCS signed transaction.
        """

        # Get account info and chain ID in parallel
        account_info, chain_id = await asyncio.gather(
            self.account(sender.address()), self.chain_id()
        )

        # Use provided sequence number or get from account
        seq_num = (
            sequence_number
            if sequence_number is not None
            else account_info["sequence_number"]
        )

        # Create raw transaction
        raw_txn = RawTransaction(
            sender=sender.account_address,
            sequence_number=seq_num,
            payload=payload,
            max_gas_amount=self.client_config.max_gas_amount,
            gas_unit_price=self.client_config.gas_unit_price,
            expiration_timestamps_secs=int(time.time())
            + self.client_config.expiration_ttl,
            chain_id=chain_id,
        )

        # Sign the transaction
        raw_txn_keyed = raw_txn.keyed()
        signature = sender.sign(raw_txn_keyed)

        # Create authenticator
        ed25519_auth = Ed25519Authenticator(
            public_key=sender.public_key(), signature=signature
        )
        authenticator = Authenticator(ed25519_auth)

        # Create signed transaction
        signed_txn = SignedTransaction(transaction=raw_txn, authenticator=authenticator)

        # Wrap in SupraTransaction and serialize
        supra_txn = SupraTransaction.create_move_transaction(signed_txn)
        supra_serializer = Serializer()
        supra_txn.serialize(supra_serializer)

        return supra_serializer.output()

    #########################
    # TRANSACTIONS WRAPPERS #
    #########################
    def create_automation_registration_tx_payload_raw_tx_object(
        self,
        sender_addr: AccountAddress,
        chain_id: int,
        sender_sequence_number: int,
        module_addr: str,
        module_name: str,
        function_name: str,
        function_type_args: List[TypeTag],
        function_args: List[bytes],
        automation_max_gas_amount: int,
        automation_gas_price_cap: int,
        automation_fee_cap_for_epoch: int,
        automation_expiration_timestamp_secs: int,
        automation_aux_data: List[bytes],
        max_gas_amount: int = 100000000,
        gas_unit_price: int = 100,
        expiration_timestamp_secs: Optional[int] = None,
    ) -> RawTransaction:
        """
        Create a raw transaction for an automation registration payload.

        This method constructs a `RawTransaction` that registers an automated
        function call with custom gas limits, fee caps, expiration, and auxiliary data.
        It builds an `EntryFunction` payload wrapped in an automation registration
        payload.

        Args:
            sender_addr (AccountAddress): The address of the transaction sender.
            chain_id (int): The chain ID for the transaction.
            sender_sequence_number (int): The sender's sequence number (nonce).
            module_addr (str): The address of the module containing the function.
            module_name (str): The name of the module.
            function_name (str): The name of the function to automate.
            function_type_args (List[TypeTag]): Type arguments for the function.
            function_args (List[bytes]): Arguments for the function.
            automation_max_gas_amount (int): Max gas allowed for automation.
            automation_gas_price_cap (int): Gas price cap for automation execution.
            automation_fee_cap_for_epoch (int): Maximum total fee for the epoch.
            automation_expiration_timestamp_secs (int): Expiration time for automation.
            automation_aux_data (List[bytes]): Auxiliary data for automation.
            max_gas_amount (int, optional): Max gas amount for the transaction.
                Defaults to 100,000,000.
            gas_unit_price (int, optional): Gas price per unit. Defaults to 100.
            expiration_timestamp_secs (Optional[int], optional): Transaction expiration
                timestamp. If not provided, defaults to current time + 600 seconds.

        Returns:
            RawTransaction: The constructed raw transaction for automation registration.
        """

        module_id = ModuleId(
            address=AccountAddress.from_str(f"0x{module_addr.zfill(64)}"),
            name=module_name,
        )

        entry_function = EntryFunction(
            module=module_id,
            function=function_name,
            ty_args=function_type_args,
            args=function_args,
        )

        v1_data = AutomationRegistrationParamsV1Data(
            automated_function=entry_function,
            max_gas_amount=automation_max_gas_amount,
            gas_price_cap=automation_gas_price_cap,
            automation_fee_cap_for_epoch=automation_fee_cap_for_epoch,
            expiration_timestamp_secs=automation_expiration_timestamp_secs,
            aux_data=automation_aux_data,
        )

        v1_params = AutomationRegistrationParamsV1(v1_data)

        automation_payload = TransactionPayloadAutomationRegistration(v1_params)

        payload = TransactionPayload(automation_payload)

        return RawTransaction(
            sender=sender_addr,
            sequence_number=sender_sequence_number,
            payload=payload,
            max_gas_amount=max_gas_amount,
            gas_unit_price=gas_unit_price,
            expiration_timestamps_secs=expiration_timestamp_secs
            or (int(time.time()) + 600),
            chain_id=chain_id,
        )

    async def send_automation_tx_using_raw_transaction(
        self,
        sender: Account,
        raw_transaction: RawTransaction,
        enable_transaction_simulation: bool = True,
        enable_wait_for_transaction: bool = True,
    ) -> Dict[str, Any]:
        """
        Sign and send an automation raw transaction.

        This method signs the provided raw transaction with the sender's key,
        optionally simulates it by breaking the signature, or submits it to the
        network and waits for confirmation.

        Args:
            sender (Account): The account signing and sending the transaction.
            raw_transaction (RawTransaction): The raw transaction to send.
            enable_transaction_simulation (bool, optional): If True, simulates the
                transaction by intentionally breaking the signature. Defaults to True.
            enable_wait_for_transaction (bool, optional): If True, waits for the
                transaction to complete. Defaults to True.

        Returns:
            Dict[str, Any]: The result of the simulation or submission.
        """

        signature = sender.sign(raw_transaction.keyed())

        if enable_transaction_simulation:
            # Intentionally break the signature for simulation
            signature = sender.sign(b"wrong_data_to_break_signature")
            print("Transaction Simulation Done")

        ed25519_auth = Ed25519Authenticator(
            public_key=sender.public_key(), signature=signature
        )
        authenticator = Authenticator(ed25519_auth)
        signed_txn = SignedTransaction(
            transaction=raw_transaction, authenticator=authenticator
        )

        if enable_wait_for_transaction:
            print("Transaction Request Sent, Waiting For Completion")

        if enable_transaction_simulation:
            return await self.simulate_bcs_txn(signed_txn)

        return await self.submit_bcs_txn(signed_txn)

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

        if simulate:
            raw_txn = await self.create_bcs_transaction(
                sender=sender,
                payload=TransactionPayload(payload),
                sequence_number=sequence_number,
            )
            broken_signature = sender.sign(b"wrong_data_to_break_signature")
            ed25519_auth = Ed25519Authenticator(
                public_key=sender.public_key(), signature=broken_signature
            )
            authenticator = Authenticator(ed25519_auth)
            signed_transaction = SignedTransaction(raw_txn, authenticator)

            return await self.simulate_bcs_txn(transaction_data=signed_transaction)
        else:
            signed_transaction = await self.create_bcs_signed_transaction(
                sender, TransactionPayload(payload), sequence_number=sequence_number
            )

            return await self.submit_bcs_txn(signed_transaction)

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
            TransactionArgument(
                task_indexes,
                lambda serializer, vals: serializer.sequence(vals, Serializer.u64),
            ),
        ]

        # Based on: automation_registry_stop_tasks(task_indexes) from Rust
        payload = EntryFunction.natural(
            "0x1::automation_registry",  # Standard library automation registry module
            "stop_tasks",  # Function name in the module
            [],  # No type arguments needed
            transaction_arguments,  # The task_indexes argument (vector<u64>)
        )

        if simulate:
            raw_txn = await self.create_bcs_transaction(
                sender=sender,
                payload=TransactionPayload(payload),
                sequence_number=sequence_number,
            )
            broken_signature = sender.sign(b"wrong_data_to_break_signature")
            ed25519_auth = Ed25519Authenticator(
                public_key=sender.public_key(), signature=broken_signature
            )
            authenticator = Authenticator(ed25519_auth)
            signed_transaction = SignedTransaction(raw_txn, authenticator)

            return await self.simulate_bcs_txn(transaction_data=signed_transaction)

        else:
            signed_transaction = await self.create_bcs_signed_transaction(
                sender, TransactionPayload(payload), sequence_number=sequence_number
            )

            return await self.submit_bcs_txn(signed_transaction)

    # :!:>bcs_transfer
    async def bcs_transfer(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer SupraCoin to a recipient using a BCS signed transaction.

        This method builds an `EntryFunction` payload for transferring the default
        SupraCoin, signs it with the sender's account, and submits it to the network.

        Args:
            sender (Account): The account sending the coins.
            recipient (AccountAddress): The recipient's account address.
            amount (int): The amount of coins to transfer.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

        Returns:
            str: The hash of the submitted transaction.
        """

        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        # <:!:bcs_transfer
        return await self.submit_bcs_txn(signed_transaction)

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer a specified coin type to a recipient.

        This method builds a coin transfer payload for any supported coin type,
        signs it with the sender's account, and submits it to the network.

        Args:
            sender (Account): The account sending the coins.
            recipient (AccountAddress): The recipient's account address.
            coin_type (str): The fully-qualified coin type tag (e.g., '0x1::supra_coin::SupraCoin').
            amount (int): The amount of coins to transfer.
            sequence_number (Optional[int], optional): The sender's sequence number.
                If not provided, it will be fetched automatically.

        Returns:
            str: The hash of the submitted transaction.
        """

        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str(coin_type))],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_txn(signed_transaction)

    async def transfer_object(
        self, owner: Account, object: AccountAddress, to: AccountAddress
    ) -> str:
        """
        Transfer an object to another account.

        This method builds an object transfer payload, signs it with the owner's
        account, and submits it to the network.

        Args:
            owner (Account): The owner account sending the object.
            object (AccountAddress): The address of the object to transfer.
            to (AccountAddress): The recipient's account address.

        Returns:
            str: The hash of the submitted transaction.
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
        return await self.submit_bcs_txn(signed_transaction)

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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - NIL", resp.status_code)
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status_code)
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {height}", resp.status_code)
        return resp.json()

    async def txs_by_block(
        self, block_hash: str, transaction_type: Optional[TransactionType] = None
    ) -> List:
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status_code)
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
        if resp.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(f"{resp.text}", resp.status_code)
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

    async def current_timestamp(self) -> float:
        block_info = await self.latest_block()
        return (
            float(block_info["header"]["timestamp"]["microseconds_since_unix_epoch"])
            / 1_000_000
        )

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

        endpoint = f"rpc/v2/tables/{table_handle.__str__()}/item"
        content = (
            table_item_request.to_params() if table_item_request is not None else {}
        )

        resp = await self._post(
            endpoint=endpoint,
            data=content,
            headers={"content-type": "application/json"},
        )

        if resp.status_code >= HTTPStatus.BAD_REQUEST:
            raise ApiError(
                f"{resp.text} - table_handle: {table_handle}", resp.status_code
            )
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {data}", resp.status_code)
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - {event_type} || {query}", resp.status_code)
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

        endpoint = f"rpc/v1/wallet/faucet/{address.__str__()}"

        resp = await self._get(endpoint=endpoint)
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(
                f"{resp.text} - account_address: {address}", resp.status_code
            )
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
        if resp.status_code != HTTPStatus.OK:
            raise ApiError(f"{resp.text} - hash: {hash}", resp.status_code)
        return resp.json()

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
        return await self.rest_client.client.get(
            url=f"{self.base_url}/{endpoint}", params=params, headers=headers
        )


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


#########
# TESTS #
#########


class AccountTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"
        self.test_account = Account.generate()
        self.test_account_address = self.test_account.account_address.__str__()
        self.bad_address = (
            "1ac1a26e27b175ebf3132e255f97182408442bef0879679626211e45f33dbf88"
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)
        self.faucet_client = FaucetClient(self.faucet_url, self.client)
        faucet_response = await self.faucet_client.faucet(
            address=self.test_account.account_address
        )
        await self.client.wait_for_transaction(faucet_response["Accepted"])

    async def test_chain_id(self):
        res = await self.client.chain_id()
        self.assertIsInstance(res, int, "FAIL: ChainId wrong data-type")
        self.assertEqual(res, 255, "FAIL: ChainId value incorrect")

    async def test_account(self):
        # invalid test case
        with self.assertRaises(Exception) as cm:
            await self.client.account(
                account_address=AccountAddress(bytes.fromhex(self.bad_address))
            )
        self.assertIn(self.bad_address, str(cm.exception))

        # valid test case
        res = await self.client.account(
            account_address=self.test_account.account_address
        )

        self.assertIsInstance(res, dict, "FAIL: Account wrong data-type")
        self.assertEqual(
            res["sequence_number"], 0, "FAIL:> New Acocint must have Sequence no. = 0"
        )
        self.assertIsNot(
            len(res["authentication_key"]), 0, "FAIL: Must havve authentication key"
        )

    async def test_account_balance(self):
        data = {
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::supra_coin::SupraCoin"],
            "arguments": [f"{self.test_account.account_address.__str__()}"],
        }
        res = await self.client.account_balance(data)
        self.assertEqual(res, 500000000)

    async def test_account_sequesnce_number(self):
        res = await self.client.account_sequence_number(
            self.test_account.account_address
        )
        self.assertEqual(res, 0, "FAIL: Initial Seq no. of a new account must be 0")

    async def test_account_transaction(self):
        pagination = AccountTxPaginationWithOrder(count=99, start=0, ascending=True)
        res = await self.client.account_transaction(
            account_address=self.test_account.account_address,
            pagination_with_order=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Transaction wrong data-type")

    async def test_account_automated_transaction(self):
        # PPS Improvement: Create an automated txn then call the fn
        pagination = AccountAutomatedTxPagination(ascending=True)
        res = await self.client.account_automated_transactions(
            address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, tuple, "FAIL: Automated Transaction wrong data-type")

    async def test_coin_transaction(self):
        pagination = AccountCoinTxPaginationWithOrder(ascending=True)
        res = await self.client.coin_transaction(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_resources(self):
        pagination = AccountPublishedListPagination()
        res = await self.client.account_resources(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_modules(self):
        pagination = AccountPublishedListPagination()
        res = await self.client.account_modules(
            account_address=self.test_account.account_address,
            pagination=pagination,
        )
        self.assertIsInstance(res, list, "FAIL: Automated Transaction wrong data-type")

    async def test_account_specific_resource(self):
        resource_struct_tag = "0x1::account::Account"

        path_param = (
            self.test_account.account_address,
            resource_struct_tag,
        )
        res = await self.client.account_specific_resource(path_param=path_param)
        self.assertIsInstance(res, dict, "fail: automated transaction wrong data-type")
        self.assertEqual(
            res["type"], resource_struct_tag, "FAIL: Wrong Resource Struct tag recvd"
        )

    async def test_account_specific_modules(self):
        """
        Currently `test_account` doesn't have any modules
        """

    async def test_aggregator_value_valid_data(self):
        """Test aggregator_value with valid data - this tests the error handling for non-aggregator resources"""
        # The coin balance is stored as a simple value, not an aggregator
        # So this test validates that the method correctly identifies when aggregator structure is missing
        resource_type = "0x1::coin::CoinStore<0x1::supra_coin::SupraCoin>"
        aggregator_path = ["coin"]

        with self.assertRaises(Exception) as cm:
            await self.client.aggregator_value(
                account_address=self.test_account.account_address,
                resource_type=resource_type,
                aggregator_path=aggregator_path,
            )

        error_msg = str(cm.exception)
        # Should get "aggregator not found" because coin.value is a simple string, not an aggregator
        self.assertIn("aggregator not found", error_msg)
        # The actual coin value should be in the error
        self.assertIn("500000000", error_msg)

    async def test_aggregator_value_invalid_resource(self):
        """Test aggregator_value with invalid resource type"""
        invalid_resource = "0x1::nonexistent::Resource"
        aggregator_path = ["coin", "value"]

        with self.assertRaises(Exception) as cm:
            await self.client.aggregator_value(
                account_address=self.test_account.account_address,
                resource_type=invalid_resource,
                aggregator_path=aggregator_path,
            )
        self.assertIn("Information not available", str(cm.exception))

    async def test_aggregator_value_invalid_path(self):
        """Test aggregator_value with invalid aggregator path"""
        # Use a valid resource but invalid path
        resource_type = "0x1::account::Account"
        invalid_path = ["nonexistent", "path"]

        with self.assertRaises(Exception) as cm:
            await self.client.aggregator_value(
                account_address=self.test_account.account_address,
                resource_type=resource_type,
                aggregator_path=invalid_path,
            )
        self.assertIn("aggregator path not found", str(cm.exception))

    async def asyncTearDown(self):
        await self.client.close()
        await self.faucet_client.close()


class TransactionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"

        self.test_account = Account.generate()
        self.test_signer_account = Account.generate()
        self.test_authenticator_account = Account.generate()
        self.test_account_address = self.test_account.account_address.__str__()[2:]
        self.test_signer_address = self.test_signer_account.account_address.__str__()[
            2:
        ]
        self.test_authenticator_address = (
            self.test_authenticator_account.account_address.__str__()[2:]
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )
        self.client = RestClient(self.base_url, self.client_config)
        self.faucet_client = RestClient(self.faucet_url, self.client_config)

        # Make faucet trnsaction(Will make a test account)
        self.faucet_client = FaucetClient(self.faucet_url, self.client)
        faucet_response_1 = await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_signer_address))
        )
        await self.client.wait_for_transaction(faucet_response_1["Accepted"])
        faucet_response_2 = await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_authenticator_address))
        )
        await self.client.wait_for_transaction(faucet_response_2["Accepted"])
        faucet_response_3 = await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_account_address))
        )
        await self.client.wait_for_transaction(faucet_response_3["Accepted"])
        faucet_response_4 = await self.faucet_client.faucet(
            address=self.test_account.account_address
        )
        await self.client.wait_for_transaction(faucet_response_4["Accepted"])

    async def test_estimate_gas_price(self):
        res = await self.client.estimate_gas_price()
        self.assertGreater(res["mean_gas_price"], 0, "FAIL: Wrong data recvd")
        self.assertGreater(res["max_gas_price"], 0, "FAIL: Wrong data recvd")
        self.assertGreater(res["median_gas_price"], 0, "FAIL: Wrong data recvd")

    async def test_transaction_parameters(self):
        res = await self.client.transaction_parameters()
        self.assertIsInstance(res, dict, "fail: automated transaction wrong data-type")
        self.assertGreater(
            res["max_transaction_time_to_live_seconds"], 0, "FAIL: Wrong data recvd"
        )

    async def test_simulate_txn(self):
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        move_txn = self.create_move_txn(
            sender=self.test_account,
            signer=self.test_authenticator_account,
            account_info=account,
            chain_id=chain_id,
            break_signature=True,
        )
        res = await self.client.simulate_tx(transaction_data=move_txn)
        self.assertEqual(
            res["status"], "Invalid", "FAIL: Status of simulated txn must be `Invalid`"
        )

    async def test_simulate_bcs_transaction(self) -> MoveTransaction:
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        bcs_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_authenticator_account,
            account_info=account,
            chain_id=chain_id,
            break_signature=True,
        )

        res = await self.client.simulate_bcs_txn(transaction_data=bcs_txn)
        self.assertEqual(
            res["status"],
            "Success",
            "FAIL: Status of proper simulated txn must be `Success`",
        )

    async def test_submit_txn(self):
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        move_txn = self.create_move_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )

        res = await self.client.submit_txn(transaction_data=move_txn)
        self.assertEqual(len(res), 66, "FAIL: txn hash length must be 66")

    async def test_submit_bcs_transaction(self) -> MoveTransaction:
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        bcs_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )
        res = await self.client.submit_bcs_txn(transaction_data=bcs_txn)
        self.assertEqual(len(res), 66, "FAIL: txn hash length must be 66")

    async def test_create_bcs_transaction(self):
        transaction_arguments = [
            TransactionArgument(
                self.test_signer_account.account_address, Serializer.struct
            ),
            TransactionArgument(1_000, Serializer.u64),
        ]

        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::coin",
                "transfer",
                [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
                transaction_arguments,
            )
        )

        raw_txn = await self.client.create_bcs_transaction(
            sender=self.test_account, payload=payload
        )

        raw_txn_keyed = raw_txn.keyed()
        signature = self.test_account.sign(raw_txn_keyed)

        ed25519_auth = Ed25519Authenticator(
            public_key=self.test_account.public_key(), signature=signature
        )
        authenticator = Authenticator(ed25519_auth)

        signed_txn = SignedTransaction(transaction=raw_txn, authenticator=authenticator)

        res = await self.client.submit_bcs_txn(transaction_data=signed_txn)
        await self.client.wait_for_transaction(res)
        self.assertEqual(len(res), 66, "FAIL: txn hash length must be 66")

    async def test_create_bcs_signed_transaction(self):
        fresh_account = Account.generate()
        faucet_resp = await self.faucet_client.faucet(
            address=fresh_account.account_address
        )
        await self.client.wait_for_transaction(faucet_resp["Accepted"])

        transaction_arguments = [
            TransactionArgument(
                self.test_signer_account.account_address, Serializer.struct
            ),
            TransactionArgument(1_000, Serializer.u64),
        ]

        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::coin",
                "transfer",
                [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
                transaction_arguments,
            )
        )

        bcs_txn_bytes = await self.client.create_bcs_signed_transaction(
            sender=fresh_account, payload=payload
        )

        self.assertIsInstance(bcs_txn_bytes, bytes)
        self.assertGreater(
            len(bcs_txn_bytes), 0, "FAIL: BCS transaction bytes should not be empty"
        )

        res = await self.client.submit_bcs_txn(transaction_data=bcs_txn_bytes)
        await self.client.wait_for_transaction(res)
        self.assertEqual(len(res), 66, "FAIL: txn hash length must be 66")

    async def test_transaction_by_hash(self):
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        move_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )
        hash = await self.client.submit_bcs_txn(transaction_data=move_txn)
        await self.client.wait_for_transaction(hash)

        res = await self.client.transaction_by_hash(hash)
        self.assertEqual(
            res["hash"], hash, "FAIL: Hash of cannot change after submission"
        )

    async def test_transaction_pending(self):
        """Test transaction_pending method"""
        # First create and submit a transaction
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        bcs_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )
        txn_hash = await self.client.submit_bcs_txn(transaction_data=bcs_txn)

        # Test with valid transaction hash - might be pending initially
        is_pending = await self.client.transaction_pending(txn_hash)
        self.assertIsInstance(
            is_pending, bool, "FAIL: transaction_pending should return boolean"
        )

        # Wait a bit and check again - should eventually not be pending
        await asyncio.sleep(2)
        is_pending_later = await self.client.transaction_pending(txn_hash)
        self.assertIsInstance(
            is_pending_later, bool, "FAIL: transaction_pending should return boolean"
        )

        # Test with non-existent transaction hash
        fake_hash = "0x" + "0" * 64
        is_pending_fake = await self.client.transaction_pending(fake_hash)
        self.assertTrue(
            is_pending_fake,
            "FAIL: Non-existent transaction should be considered pending",
        )

    async def test_wait_for_transaction(self):
        """Test wait_for_transaction method"""
        # Create and submit a transaction
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        move_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )
        txn_hash = await self.client.submit_bcs_txn(transaction_data=move_txn)

        # Wait for transaction should complete without error
        await self.client.wait_for_transaction(txn_hash)

        # After waiting, transaction should not be pending
        is_pending = await self.client.transaction_pending(txn_hash)
        self.assertFalse(
            is_pending,
            "FAIL: Transaction should not be pending after wait_for_transaction",
        )

        # Transaction should have success status
        txn_data = await self.client.transaction_by_hash(txn_hash)
        self.assertEqual(
            txn_data.get("status"),
            "Success",
            "FAIL: Transaction should have Success status",
        )

    async def test_submit_and_wait_for_bcs_transaction(self):
        """Test submit_and_wait_for_bcs_transaction method"""
        # Create a BCS transaction
        account = await self.client.account(
            account_address=self.test_account.account_address
        )
        chain_id = await self.client.chain_id()

        bcs_txn = self.create_bcs_txn(
            sender=self.test_account,
            signer=self.test_account,
            account_info=account,
            chain_id=chain_id,
        )

        # Submit and wait for the BCS transaction
        result = await self.client.submit_and_wait_for_bcs_transaction(bcs_txn)

        # Result should be a dictionary with transaction details
        self.assertIsInstance(
            result, dict, "FAIL: submit_and_wait_for_bcs_transaction should return dict"
        )
        self.assertIn("hash", result, "FAIL: Result should contain transaction hash")
        self.assertIn(
            "status", result, "FAIL: Result should contain transaction status"
        )
        self.assertEqual(
            result.get("status"),
            "Success",
            "FAIL: Transaction should have Success status",
        )

        # Hash should be 66 characters (0x + 64 hex chars)
        self.assertEqual(
            len(result["hash"]), 66, "FAIL: Transaction hash should be 66 characters"
        )

        # Transaction should not be pending after submit_and_wait
        is_pending = await self.client.transaction_pending(result["hash"])
        self.assertFalse(
            is_pending, "FAIL: Transaction should not be pending after submit_and_wait"
        )

    async def test_bcs_transfer(self):
        """Test bcs_transfer method"""
        # Create a fresh account to transfer to
        recipient_account = Account.generate()
        resp = await self.faucet_client.faucet(
            address=recipient_account.account_address
        )
        await self.client.wait_for_transaction(resp["Accepted"])

        # Get initial balances
        sender_balance_data = {
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::supra_coin::SupraCoin"],
            "arguments": [str(self.test_account.account_address)],
        }
        initial_sender_balance = await self.client.account_balance(sender_balance_data)

        recipient_balance_data = {
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::supra_coin::SupraCoin"],
            "arguments": [str(recipient_account.account_address)],
        }
        initial_recipient_balance = await self.client.account_balance(
            recipient_balance_data
        )

        # Transfer amount
        transfer_amount = 10_000_000

        # Perform transfer
        txn_hash = await self.client.bcs_transfer(
            sender=self.test_account,
            recipient=recipient_account.account_address,
            amount=transfer_amount,
        )

        # Verify transaction hash format
        self.assertEqual(
            len(txn_hash), 66, "FAIL: Transaction hash should be 66 characters"
        )
        self.assertTrue(
            txn_hash.startswith("0x"), "FAIL: Transaction hash should start with 0x"
        )

        # Wait for transaction completion
        await self.client.wait_for_transaction(txn_hash)

        # Verify balances changed correctly
        final_sender_balance = await self.client.account_balance(sender_balance_data)
        final_recipient_balance = await self.client.account_balance(
            recipient_balance_data
        )

        # Sender should have less (transfer amount + gas fees)
        self.assertLess(
            final_sender_balance,
            initial_sender_balance,
            "FAIL: Sender balance should decrease",
        )

        # Recipient should have exactly transfer_amount more
        self.assertEqual(
            final_recipient_balance,
            initial_recipient_balance + transfer_amount,
            "FAIL: Recipient should receive exact transfer amount",
        )

    async def test_transfer_coins(self):
        """Test transfer_coins method with SupraCoin"""
        # Create a fresh account to transfer to
        recipient_account = Account.generate()
        resp = await self.faucet_client.faucet(
            address=recipient_account.account_address
        )
        await self.client.wait_for_transaction(resp["Accepted"])

        # Get initial balances
        sender_balance_data = {
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::supra_coin::SupraCoin"],
            "arguments": [str(self.test_account.account_address)],
        }
        initial_sender_balance = await self.client.account_balance(sender_balance_data)

        recipient_balance_data = {
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::supra_coin::SupraCoin"],
            "arguments": [str(recipient_account.account_address)],
        }
        initial_recipient_balance = await self.client.account_balance(
            recipient_balance_data
        )

        # Transfer amount
        transfer_amount = 50_000_000

        # Perform transfer using transfer_coins
        txn_hash = await self.client.transfer_coins(
            sender=self.test_account,
            recipient=recipient_account.account_address,
            coin_type="0x1::supra_coin::SupraCoin",
            amount=transfer_amount,
        )

        # Verify transaction hash format
        self.assertEqual(
            len(txn_hash), 66, "FAIL: Transaction hash should be 66 characters"
        )
        self.assertTrue(
            txn_hash.startswith("0x"), "FAIL: Transaction hash should start with 0x"
        )

        # Wait for transaction completion
        await self.client.wait_for_transaction(txn_hash)

        # Verify balances changed correctly
        final_sender_balance = await self.client.account_balance(sender_balance_data)
        final_recipient_balance = await self.client.account_balance(
            recipient_balance_data
        )

        # Sender should have less (transfer amount + gas fees)
        self.assertLess(
            final_sender_balance,
            initial_sender_balance,
            "FAIL: Sender balance should decrease",
        )

        # Recipient should have exactly transfer_amount more
        self.assertEqual(
            final_recipient_balance,
            initial_recipient_balance + transfer_amount,
            "FAIL: Recipient should receive exact transfer amount",
        )

    def create_move_txn(
        self,
        sender: Account,
        signer: Account,
        account_info: dict,
        chain_id: int,
        break_signature: bool = False,
    ):
        payload = TransactionPayload(
            EntryFunction(
                module=ModuleId(
                    address=AccountAddress.from_str("0x1"),
                    name="coin",
                ),
                function="transfer",
                ty_args=[],
                args=[],
            )
        )

        raw_txn = RawTransaction(
            sender=sender.account_address,
            sequence_number=account_info["sequence_number"],
            payload=payload,
            max_gas_amount=10000,
            gas_unit_price=100,
            expiration_timestamps_secs=int(time.time()) + 600,
            chain_id=chain_id,
        )

        account_authenticator = signer.sign_transaction(raw_txn)
        if account_authenticator.variant == AccountAuthenticator.ED25519:
            ed25519_auth = (
                account_authenticator.authenticator
            )  # This is Ed25519Authenticator
            public_key_hex = ed25519_auth.public_key.to_crypto_bytes().hex()
            signature_hex = str(ed25519_auth.signature)

            if break_signature:
                signature_hex = "0" * 128

            auth_data = {
                "Ed25519": {
                    "public_key": public_key_hex,
                    "signature": signature_hex,
                }
            }
        else:
            print(f"Unexpected authenticator variant: {account_authenticator.variant}")

        return MoveTransaction(raw_transaction=raw_txn, authenticator_data=auth_data)

    def create_bcs_txn(
        self,
        sender: Account,
        signer: Account,
        account_info: dict,
        chain_id: int,
        break_signature: bool = False,
    ) -> bytes:
        serializer = Serializer()

        transaction_arguments = [
            TransactionArgument(
                self.test_signer_account.account_address, Serializer.struct
            ),
            TransactionArgument(1_000, Serializer.u64),
        ]

        payload = TransactionPayload(
            EntryFunction.natural(
                "0x1::coin",
                "transfer",
                [TypeTag(StructTag.from_str("0x1::supra_coin::SupraCoin"))],
                transaction_arguments,
            )
        )

        payload.serialize(serializer)
        payload_bytes = serializer.output()

        if payload_bytes[0] > 2:
            print(f"ERROR: Invalid payload variant {payload_bytes[0]} for Supra")
            return

        raw_txn = RawTransaction(
            sender=sender.account_address,
            sequence_number=account_info["sequence_number"],
            payload=payload,
            max_gas_amount=10000,
            gas_unit_price=100,
            expiration_timestamps_secs=int(time.time()) + 600,
            chain_id=chain_id,
        )

        raw_txn_keyed = raw_txn.keyed()

        if break_signature:
            signature = signer.sign(b"wrong_data_to_break_signature")
        else:
            signature = signer.sign(raw_txn_keyed)

        ed25519_auth = Ed25519Authenticator(
            public_key=sender.public_key(), signature=signature
        )
        authenticator = Authenticator(ed25519_auth)

        signed_txn = SignedTransaction(transaction=raw_txn, authenticator=authenticator)

        # Wrap in SupraTransaction
        supra_txn = SupraTransaction.create_move_transaction(signed_txn)

        supra_serializer = Serializer()
        supra_txn.serialize(supra_serializer)
        return supra_serializer.output()

    async def asyncTearDown(self):
        await self.client.close()
        await self.faucet_client.close()


class BlockTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_latest_block(self):
        res = await self.client.latest_block()
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

    async def test_block_info_by_hash(self):
        latest_block = await self.client.latest_block()
        correct_hash = latest_block["header"]["hash"]
        wrong_hash = "0x" + latest_block["header"]["hash"][::-1][:-2]

        # Correct block info
        res = await self.client.block_info_by_hash(block_hash=correct_hash)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

        with self.assertRaises(Exception) as cm:
            res = await self.client.block_info_by_hash(block_hash=wrong_hash)
        self.assertIn(wrong_hash, str(cm.exception))

    async def test_block_by_height(self):
        latest_block = await self.client.latest_block()
        latest_height = latest_block["header"]["height"]
        correct_height = latest_height - 1
        wrong_height = latest_height + 1000

        res = await self.client.block_by_height(height=correct_height)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(
            len(res["header"]["hash"]), 0, "FAIL: Block hash cannot be empty"
        )

        with self.assertRaises(Exception) as cm:
            res = await self.client.block_by_height(height=wrong_height)
        self.assertIn(str(wrong_height), str(cm.exception))

    async def test_txs_by_block(self):
        latest_block = await self.client.latest_block()
        correct_hash = latest_block["header"]["hash"]
        wrong_hash = "0x" + latest_block["header"]["hash"][::-1][:-2]

        # Correct block info
        res = await self.client.txs_by_block(block_hash=correct_hash)
        self.assertIsInstance(res, list, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res[0]), 0, "FAIL: Block hash cannot be empty")

        with self.assertRaises(Exception) as cm:
            res = await self.client.txs_by_block(block_hash=wrong_hash)
        self.assertIn(wrong_hash, str(cm.exception))

    async def asyncTearDown(self):
        await self.client.close()


class TablesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # local network
        self.base_url = "http://localhost:27000"
        self.faucet_url = "http://localhost:27001"
        self.test_address = (
            "88FBD33F54E1126269769780FEB24480428179F552E2313FBE571B72E62A1CA1"
        )

        # Make client
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

        # Make faucet trnsaction(Will make a test account)
        self.faucet_client = FaucetClient(self.faucet_url, self.client)
        faucet_response = await self.faucet_client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )
        await self.client.wait_for_transaction(faucet_response["Accepted"])

    async def test_items_by_key(self):
        tir = TableItemRequest(
            key_type="u64",
            value_type="0x1::multisig_voting::Proposal<0x1::governance_proposal::GovernanceProposal>",
            key="12",
        )

        with self.assertRaises(Exception) as cm:
            _res = await self.client.table_items_by_key(
                table_handle=AccountAddress(bytes.fromhex(self.test_address)),
                table_item_request=tir,
            )
        self.assertIn(self.test_address.lower(), str(cm.exception))

    async def asyncTearDown(self):
        await self.client.close()
        await self.faucet_client.close()


class ViewTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_view_function(self):
        data = {
            "function": "0x1::timestamp::now_microseconds",
            "type_arguments": [],
            "arguments": [],
        }

        res = await self.client.view_function(data=data)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res["result"][0]), 0, "FAIL: timestamp cannot be 0")

    async def asyncTearDown(self):
        await self.client.close()


class EventsTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = RestClient(self.base_url, self.client_config)

    async def test_events_by_type(self):
        event_type = "0x1::coin::CoinDeposit"
        res = await self.client.events_by_type(event_type=event_type)
        self.assertIsInstance(res, dict, "FAIL: Wrong data-type returned")
        self.assertGreater(len(res["data"]), 0, "FAIL: timestamp cannot be 0")

    async def asyncTearDown(self):
        await self.client.close()


class FaucetTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.base_url = "http://localhost:27001"
        self.test_address = (
            "88FBD33F54E1126269769780FEB24480428179F552E2313FBE571B72E62A1CA1"
        )

        self.client_config = ClientConfig(
            expiration_ttl=600,
            gas_unit_price=100,
            max_gas_amount=100_000,
        )

        self.client = FaucetClient(
            self.base_url, RestClient(self.base_url, self.client_config)
        )

    async def test_faucet(self):
        res = await self.client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )
        self.assertIsInstance(res, dict, "FAIL: wrong result data-type")
        self.assertGreater(len(res["Accepted"]), 0, "FAIL: Must return a hash")

    async def test_faucet_txn_by_hash(self):
        res = await self.client.faucet(
            address=AccountAddress(bytes.fromhex(self.test_address))
        )
        hash = res["Accepted"]

        res = await self.client.faucet_transaction_by_hash(hash=hash)
        self.assertIsInstance(res, dict, "FAIL: wrong result data-type")
        self.assertEqual(res["hash"], hash, "FAIL: Hash must be present")

    async def asyncTearDown(self):
        await self.client.close()
