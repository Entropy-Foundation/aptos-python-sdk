from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

MAX_NUM_OF_TRANSACTIONS_TO_RETURN: int = 100
DEFAULT_SIZE_OF_PAGE: int = 20


class SupraRestAcceptType(str, Enum):
    JSON = "application/json"
    OCTET = "application/octet-stream"
    BCS = "application/x-bcs"


class TransactionType(str, Enum):
    AUTO = "auto"
    USER = "user"
    META = "meta"


@dataclass
class ConsensusBlockByHeightQuery:
    with_batches: bool = False

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        params["with_batches"] = str(self.with_batches).lower()
        return params


@dataclass
class TableItemRequest:
    """
    Represents a request for querying a specific item from a Move table.

    Attributes:
        key_type (Optional[str]): The type of the table key.
        value_type (Optional[str]): The type of the table value.
        key (Optional[str]): The key to fetch from the table.
    """

    key_type: str
    value_type: str
    key: Any

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the TableItemRequest into a dictionary of parameters for an HTTP request.

        Returns:
            Dict[str, Any]: Dictionary containing non-null fields as request parameters.
        """

        params: Dict[str, Any] = {}
        params["key_type"] = self.key_type
        params["value_type"] = self.value_type
        params["key"] = self.key
        return params


@dataclass
class PaginationWithOrder:
    """
    Generic pagination parameters with ordering.

    Attributes:
        count: Maximum number of items to return.
        start: Starting point or cursor for pagination.
        ascending: If True, results are in ascending order.
    """

    count: Optional[int] = None
    start: Optional[int] = None
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.
        """
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        params["ascending"] = str(self.ascending).lower()
        return params


class AccountTxPaginationWithOrder(PaginationWithOrder):
    """Pagination parameters for account transactions."""


class AccountCoinTxPaginationWithOrder(PaginationWithOrder):
    """Pagination parameters for account coin transactions."""


@dataclass
class AccountPublishedListPagination:
    """
    Pagination options for listing published items associated with an account.

    Attributes:
        count (Optional[int]): Maximum number of items to return. Default is 20.
        start (Optional[List[int]]): Cursor specifying where to start for pagination.
    """

    count: Optional[int] = None
    start: Optional[List[int]] = None

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.
        """
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        return params


@dataclass
class AccountAutomatedTxPagination:
    """
    Pagination options for automated transactions, supporting both block height and cursor.

    Attributes:
        count (Optional[int]): Maximum number of items to return. Default is 20.
        block_height (Optional[int]): Starting block height (inclusive).
        cursor (Optional[str]): The cursor (exclusive) to start the query from.
        ascending (bool): Flag indicating order of lookup. Defaults to False (descending).
    """

    count: Optional[int] = None
    block_height: Optional[int] = None
    cursor: Optional[str] = None
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.
        """
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.block_height is not None:
            params["block_height"] = self.block_height
        if self.cursor is not None:
            params["cursor"] = self.cursor
        params["ascending"] = str(self.ascending).lower()
        return params


class EventQuery:
    """
    Defines query parameters for fetching events over a block range.

    Attributes:
        start_height (Optional[int]): Starting block height (inclusive).
        end_height (Optional[int]): Ending block height (exclusive).
        limit (Optional[int]): Maximum number of events to return.
        start (Optional[str]): Cursor to start the query from.
    """

    start_height: Optional[int]
    end_height: Optional[int]
    limit: Optional[int]
    start: Optional[str] = None

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the event query configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.
        """
        params: Dict[str, Any] = {}
        if self.start_height:
            params["start_height"] = self.start_height
        if self.end_height is not None:
            params["end_height"] = self.end_height
        if self.limit is not None:
            params["limit"] = self.limit
        if self.start is not None:
            params["start"] = self.start
        return params
