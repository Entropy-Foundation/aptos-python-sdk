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
    """
    Represents pagination options for coin transactions in an account, including ordering.

    Attributes:
        count (Optional[int]): Maximum number of items to return. Default is 20.
        start (Optional[int]): The cursor (exclusive) that the search should start from.
        ascending (bool): Flag indicating order of lookup. Defaults to False (descending).
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
        if self.start_height is not None:
            params["start_height"] = self.start_height
        if self.end_height is not None:
            params["end_height"] = self.end_height
        if self.limit is not None:
            params["limit"] = self.limit
        if self.start is not None:
            params["start"] = self.start
        return params
