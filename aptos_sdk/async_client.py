# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
import python_graphql_client

from .account_address import AccountAddress
from .api_types import (
    AccountAutomatedTxPagination,
    AccountCoinTxPaginationWithOrder,
    AccountPublishedListPagination,
    AccountTxPaginationWithOrder,
    EventQuery,
    SupraRestAcceptType,
    TransactionType,
)
from .metadata import Metadata

U64_MAX = 18446744073709551615


@dataclass
class ClientConfig:
    """Common configuration for clients, particularly for submitting transactions"""

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
        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = python_graphql_client.GraphqlClient(
            endpoint=indexer_url, headers=headers
        )

    async def query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        return await self.client.execute_async(query, variables)


class RestClient:
    """A wrapper around the Aptos-core Rest API"""

    _chain_id: Optional[int]
    client: httpx.AsyncClient
    client_config: ClientConfig
    base_url: str

    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
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
        await self.client.aclose()

    async def chain_id(self):
        if not self._chain_id:
            info = await self.info()
            self._chain_id = int(info["chain_id"])
        return self._chain_id

    ###########
    # ACCOUNT #
    ###########

    async def get_account_v3(
        self,
        account_address: AccountAddress,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, str]:
        """GET /rpc/v3/accounts/{address}"""
        endpoint = f"rpc/v3/accounts/{account_address}"
        headers = {"Accept": accept_type}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)

        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def get_account_transaction_v3(
        self,
        account_address: AccountAddress,
        pagination_with_order: Optional[AccountTxPaginationWithOrder] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        endpoint = f"rpc/v3/accounts/{account_address}/transactions"
        headers = {"Accept": accept_type}
        params = pagination_with_order.to_params() if pagination_with_order else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def get_account_automated_transactions_v3(
        self,
        address: AccountAddress,
        pagination: Optional[AccountAutomatedTxPagination] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
        # TODO: Add return type
    ):
        """GET /rpc/v3/accounts/{address}/automated_transactions"""
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )

        endpoint = f"rpc/v3/accounts/{address}/automated_transactions"
        headers = {"Accept": accept_type}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        data = resp.json()
        # TODO: need to extract Txn data form `data`
        resp_cursor = resp.headers.get("x-supra-cursor", "")

        return data, resp_cursor

    async def coin_transaction_v3(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountCoinTxPaginationWithOrder] = None,
        # txn_type: None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/coin_transactions"
        headers = {"Accept": accept_type}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def get_account_resources_v3(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/resources"
        headers = {"Accept": accept_type}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def get_account_modules_v3(
        self,
        account_address: AccountAddress,
        pagination: Optional[AccountPublishedListPagination] = None,
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(
            accept_type,
            [SupraRestAcceptType.BCS.value, SupraRestAcceptType.OCTET.value],
        )
        endpoint = f"rpc/v3/accounts/{account_address}/modules"
        headers = {"Accept": accept_type}
        params = pagination.to_params() if pagination else {}

        resp = await self._get(endpoint=endpoint, headers=headers, params=params)

        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {account_address}", resp.status)
        return resp.json()

    async def get_account_specific_resource_v3(
        self,
        path_param: Tuple[AccountAddress, str],
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(accept_type, [SupraRestAcceptType.OCTET.value])
        address, tag_string = path_param[0], path_param[1]
        endpoint = f"rpc/v3/accounts/{address}/resources/{tag_string}"
        headers = {"Accept": accept_type}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {address}", resp.status)
        return resp.json()

    async def get_account_specific_modules_v3(
        self,
        path_param: Tuple[AccountAddress, str],
        accept_type: str = SupraRestAcceptType.JSON.value,
    ) -> Dict[str, Any]:
        self._check_accept_type(accept_type, [SupraRestAcceptType.OCTET.value])
        address, module_name = path_param[0], path_param[1]
        endpoint = f"rpc/v3/accounts/{address}/modules/{module_name}"
        headers = {"Accept": accept_type}

        resp = await self._get(endpoint=endpoint, headers=headers, params=None)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {address}", resp.status)
        return resp.json()

    ################
    # TRANSACTIONS #
    ################
    async def transaction_by_hash(self, hash: str) -> Dict[str, Any]:
        endpoint = f"rpc/v3/transactions/{hash}"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {hash}", resp.status)
        return resp.json()

    async def submit_txn(
        self, transaction_data: Union[Dict[str, Any], bytes]
    ) -> Dict[str, Any]:
        endpoint = "rpc/v3/transactions/submit"

        resp = await self._post(endpoint=endpoint, data=transaction_data)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status)
        return resp.json()

    async def simulate_tx(
        self, transaction_data: Union[Dict[str, Any], bytes]
    ) -> Dict[str, Any]:
        endpoint = "rpc/v3/transactions/simulate"

        resp = await self._post(endpoint=endpoint, data=transaction_data)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {transaction_data}", resp.status)
        return resp.json()

    ##########
    # BLOCKS #
    ##########
    async def latest_block(self) -> Dict[str, Any]:
        endpoint = "rpc/v3/block"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - NIL", resp.status)
        return resp.json()

    async def block_info_by_hash(self, block_hash: str) -> Dict[str, Any]:
        endpoint = f"rpc/v3/block/{block_hash}"

        resp = await self._get(endpoint=endpoint)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status)
        return resp.json()

    async def block_by_height(
        self,
        height: int,
        transaction_type: Optional[TransactionType] = None,
        with_finalized_transaction: bool = False,
    ) -> Dict[str, Any]:
        endpoint = f"rpc/v3/block/height/{height}"

        params = {"with_finalized_transactions": with_finalized_transaction}

        if transaction_type is not None:
            params["transaction_type"] = transaction_type.value

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {height}", resp.status)
        return resp.json()

    async def txs_by_block(
        self, block_hash: str, transaction_type: Optional[TransactionType] = None
    ) -> Dict[str, Any]:
        endpoint = f"rpc/v3/block/{block_hash}/transactions"

        params = {}
        if transaction_type is not None:
            params["transaction_type"] = transaction_type.value

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {block_hash}", resp.status)
        return resp.json()

    ########
    # VIEW #
    ########

    async def view_function(self, data: Union[Dict[str, Any], bytes]) -> Dict[str, Any]:
        endpoint = "rpc/v3/view"

        resp = await self._post(endpoint=endpoint, data=data)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {data}", resp.status)
        return resp.json()

    ##########
    # EVENTS #
    ##########

    async def events_by_type(
        self, event_type: str, query: Optional[EventQuery] = None
    ) -> Dict[str, Any]:
        endpoint = f"rpc/v3/events/{event_type}"

        params = query.to_params() if query is not None else {}

        resp = await self._get(endpoint=endpoint, params=params)
        if resp.status >= 400:
            raise ApiError(f"{resp.text} - {event_type} || {query}", resp.status)
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
        # format params:
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
        # format params:
        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}
        return await self.client.get(
            url=f"{self.base_url}/{endpoint}", params=params, headers=headers
        )

    def _check_accept_type(self, accept_type: str, unsupported: List[str]) -> None:
        """Check if accept type is supported (mirrors reject_unsupported_header)"""
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
        """This creates an account if it does not exist and mints the specified amount of
        coins into that account."""
        request = f"{self.base_url}/mint?amount={amount}&address={address}"
        response = await self.rest_client.client.post(request, headers=self.headers)
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        txn_hash = response.json()[0]
        if wait_for_transaction:
            await self.rest_client.wait_for_transaction(txn_hash)
        return txn_hash

    async def healthy(self) -> bool:
        response = await self.rest_client.client.get(self.base_url)
        return "tap:ok" == response.text


class ApiError(Exception):
    """The API returned a non-success status code, e.g., >= 400"""

    status_code: int

    def __init__(self, message: str, status_code: int):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.status_code = status_code


class AcceptTypeNotSupported(Exception):
    """Exception raised when an Accept type is not supported."""

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
    """The account was not found"""

    account: AccountAddress

    def __init__(self, message: str, account: AccountAddress):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.account = account


class ResourceNotFound(Exception):
    """The underlying resource was not found"""

    resource: str

    def __init__(self, message: str, resource: str):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.resource = resource
