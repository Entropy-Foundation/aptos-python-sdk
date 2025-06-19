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
class AccountCoinTxPaginationWithOrder:
    # Maximum number of items to return. Default is 20.
    count: Optional[int] = None

    # The cursor (exclusive) that the search should start from.
    # If provided, returns `:count` of transactions starting from this cursor in the specified order.
    # For order see `:ascending` flag.
    start: Optional[int] = None

    # Flag indicating order of lookup.
    # Defaults to `false` i.e. transactions are returned in descending order of their execution.
    # If `true`, transactions are returned in ascending order of their execution.
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        params["ascending"] = str(self.ascending).lower()
        return params


@dataclass
class AccountPublishedListPagination:
    # Maximum number of items to return. Default is 20.
    count: Optional[int] = None

    # Cursor specifying where to start for pagination.
    # Use the cursor returned by the API when making the next request.
    start: Optional[List[int]] = None

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        return params


@dataclass
class AccountAutomatedTxPagination:
    # Maximum number of items to return. Default is 20.
    count: Optional[int] = None

    # Starting block height (inclusive). Optional.
    # The block height at which to start lookup for transactions.
    # If provided, returns `:count` of transactions starting from it in the specified order.
    # For order see `:ascending` flag.
    # Note: If a `:cursor` is specified then this field will be ignored.
    block_height: Optional[int] = None

    # The cursor (exclusive) to start the query from. Optional.
    # If provided, returns `:count` of transactions starting from this cursor in the specified order.
    # For order see `:ascending` flag.
    # If not specified, the lookup will be done based on the `:block_height` parameter value.
    # Note: If both `:cursor` and `:block_height` are specified then `:cursor` has precedence.
    cursor: Optional[str] = None

    # Flag indicating order of lookup
    # Defaults to `false`; i.e. transactions are returned in descending order of their execution.
    # If `true`, transactions are returned in ascending order of their execution.
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.block_height is not None:
            params["block_height"] = self.block_height
        if self.cursor is not None:
            params["cursor"] = self.cursor
        params["ascending"] = str(self.ascending).lower()
        return params


@dataclass
class AccountTxPaginationWithOrder:
    """
    Pagination parameters for account transactions.

    Attributes:
        count: Maximum number of items to return. Default is 20.
        start: Starting sequence number. If provided, return :count of transactions
               starting from this sequence number (inclusive) in the specified order.
        ascending: Flag indicating order of lookup. Defaults to false; i.e. the
                  transactions are returned in descending order by sequence number.
    """

    count: Optional[int] = None
    start: Optional[int] = None
    ascending: bool = False

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.count is not None:
            params["count"] = self.count
        if self.start is not None:
            params["start"] = self.start
        params["ascending"] = str(self.ascending).lower()
        return params


class EventQuery:
    # Starting block height (inclusive). Optional.
    start_height: Optional[int]

    # Ending block height (exclusive). Optional.
    end_height: Optional[int]

    # Maximum number of events to return. Defaults to 20, max 100.
    limit: Optional[int]

    # The cursor to start the query from. Optional.
    # During a paginated query, the cursor returned in the `X_SUPRA_CURSOR` response header
    # should be specified as the `start` parameter of the request for the next page.
    start: Optional[str] = None

    def to_params(self) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if self.start_height is not None:
            params["start_height"] = self.start_height
        if self.end_height is not None:
            params["end_height"] = self.end_height
        if self.limit is not None:
            params["limit"] = self.limit
        if self.start is not None:
            params["start"] = self.start
        return params
