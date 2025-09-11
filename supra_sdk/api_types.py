# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from enum import Enum
from typing import Any

RPC_API_PREFIX = "rpc/v3"

# Account endpoints
ACCOUNT_ENDPOINT = f"{RPC_API_PREFIX}/accounts/{{account_address}}"
ACCOUNT_RESOURCE_ENDPOINT = (
    f"{RPC_API_PREFIX}/accounts/{{account_address}}/resources/{{resource_type}}"
)
ACCOUNT_RESOURCES_ENDPOINT = f"{RPC_API_PREFIX}/accounts/{{account_address}}/resources"
ACCOUNT_MODULE_ENDPOINT = (
    f"{RPC_API_PREFIX}/accounts/{{account_address}}/modules/{{module_name}}"
)
ACCOUNT_MODULES_ENDPOINT = f"{RPC_API_PREFIX}/accounts/{{account_address}}/modules"
ACCOUNT_TRANSACTIONS_ENDPOINT = (
    f"{RPC_API_PREFIX}/accounts/{{account_address}}/transactions"
)
ACCOUNT_COIN_TRANSACTIONS_ENDPOINT = (
    f"{RPC_API_PREFIX}/accounts/{{account_address}}/coin_transactions"
)
ACCOUNT_AUTOMATED_TRANSACTIONS_ENDPOINT = (
    f"{RPC_API_PREFIX}/accounts/{{account_address}}/automated_transactions"
)

# Transaction endpoints
CHAIN_ID_ENDPOINT = f"{RPC_API_PREFIX}/transactions/chain_id"
TRANSACTION_BY_HASH_ENDPOINT = f"{RPC_API_PREFIX}/transactions/{{hash}}"
TRANSACTION_ESTIMATE_GAS_PRICE_ENDPOINT = (
    f"{RPC_API_PREFIX}/transactions/estimate_gas_price"
)
TRANSACTION_PARAMETERS_ENDPOINT = f"{RPC_API_PREFIX}/transactions/parameters"
TRANSACTION_SUBMIT_TRANSACTION_ENDPOINT = f"{RPC_API_PREFIX}/transactions/submit"
TRANSACTION_SIMULATE_TRANSACTION_ENDPOINT = f"{RPC_API_PREFIX}/transactions/simulate"

# View function endpoint
VIEW_FUNCTION_ENDPOINT = f"{RPC_API_PREFIX}/view"

# Table item endpoint
TABLE_ITEMS_ENDPOINT = f"{RPC_API_PREFIX}/tables/{{table_handle}}/item"

# Events endpoints
EVENTS_BY_TYPE_ENDPOINT = f"{RPC_API_PREFIX}/events/{{event_type}}"

# Block endpoints
LATEST_BLOCK_ENDPOINT = f"{RPC_API_PREFIX}/block"
BLOCK_BY_HASH_ENDPOINT = f"{RPC_API_PREFIX}/block/{{block_hash}}"
BLOCK_BY_HEIGHT_ENDPOINT = f"{RPC_API_PREFIX}/block/height/{{height}}"
BLOCK_TRANSACTIONS_ENDPOINT = f"{RPC_API_PREFIX}/block/{{block_hash}}/transactions"

# Consensus endpoints
LATEST_CONSENSUS_BLOCK_ENDPOINT = f"{RPC_API_PREFIX}/consensus/block"
CONSENSUS_BLOCK_BY_HEIGHT_ENDPOINT = f"{RPC_API_PREFIX}/consensus/height/{{height}}"
COMMITTEE_AUTHORIZATION_ENDPOINT = (
    f"{RPC_API_PREFIX}/consensus/committee_authorization/{{epoch}}"
)

# Faucet endpoints
FAUCET_ENDPOINT = f"{RPC_API_PREFIX}/wallet/faucet/{{address}}"
FAUCET_TRANSACTION_ENDPOINT = f"{RPC_API_PREFIX}/wallet/faucet/transactions/{{hash}}"


@dataclass(frozen=True)
class Pagination:
    """Generic pagination parameters.

    Attributes:
        count: Number of items to return, default value is 20 and maximum value is 100.
            In case of `count`>100 only 100 items will be returned.
        start: Cursor or starting point specifying where to start for pagination.

    """

    count: int | None = None
    start: str | int | None = None

    def to_params(self) -> dict[str, Any]:
        """Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.

        """
        params: dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        return params


@dataclass(frozen=True)
class PaginationWithOrder(Pagination):
    """Generic pagination parameters with ordering.

    Attributes:
        ascending: Flag indicating order of lookup. If True, results are in ascending order.

    """

    ascending: bool | None = None

    def to_params(self) -> dict[str, Any]:
        """Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.

        """
        params: dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        if self.ascending is not None:
            params["ascending"] = str(self.ascending).lower()
        return params


@dataclass(frozen=True)
class AutomatedTransactionsPagination:
    """Pagination parameters for automation transaction endpoint.

    Attributes:
        ascending: Flag indicating order of lookup. If True, results are in ascending order.
        block_height: Start block height to consider for transaction retrieval.
        count: Number of items to return, default value is 20 and maximum value is 100.
            In case of `count`>100 only 100 items will be returned.

    """

    ascending: bool | None = None
    block_height: int | None = None
    count: int | None = None

    def to_params(self) -> dict[str, Any]:
        """Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.

        """
        params: dict[str, Any] = {}
        if self.ascending is not None:
            params["ascending"] = str(self.ascending).lower()
        if self.block_height is not None:
            params["block_height"] = self.block_height
        if self.count is not None:
            params["count"] = self.count
        return params


@dataclass(frozen=True)
class EventsPagination:
    """Pagination parameters for events retrieval endpoint.

    Attributes:
        start_height (Optional[int]): Starting block height (inclusive).
        end_height (Optional[int]): Ending block height (exclusive).
        limit (Optional[int]): Maximum number of events to return. Defaults to 20, max 100.
        start (Optional[str]): The cursor to start the query from.

    """

    start_height: int | None = None
    end_height: int | None = None
    limit: int | None = None
    start: str | None = None

    def to_params(self) -> dict[str, Any]:
        """Converts the event query configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.

        """
        params: dict[str, Any] = {}
        if self.start_height:
            params["start_height"] = self.start_height
        if self.end_height is not None:
            params["end_height"] = self.end_height
        if self.limit is not None:
            params["limit"] = self.limit
        if self.start is not None:
            params["start"] = self.start
        return params


class TransactionType(str, Enum):
    AUTO = "auto"
    USER = "user"
    META = "meta"
