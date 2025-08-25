from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Union


@dataclass(frozen=True)
class Pagination:
    """
    Generic pagination parameters.

    Attributes:
        count: Number of items to return, default value is 20 and maximum value is 100.
            In case of `count`>100 only 100 items will be returned.
        start: Cursor or starting point specifying where to start for pagination.
    """

    count: Optional[int] = None
    start: Optional[Union[str, int]] = None

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


@dataclass(frozen=True)
class PaginationWithOrder(Pagination):
    """
    Generic pagination parameters with ordering.

    Attributes:
        ascending: Flag indicating order of lookup. If True, results are in ascending order.
    """

    ascending: Optional[bool] = None

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
        if self.ascending is not None:
            params["ascending"] = str(self.ascending).lower()
        return params


@dataclass(frozen=True)
class AutomatedTransactionsPagination:
    """
    Pagination parameters for automation transaction endpoint.

    Attributes:
        ascending: Flag indicating order of lookup. If True, results are in ascending order.
        block_height: Start block height to consider for transaction retrival.
        count: Number of items to return, default value is 20 and maximum value is 100.
            In case of `count`>100 only 100 items will be returned.
    """

    ascending: Optional[bool] = None
    block_height: Optional[int] = None
    count: Optional[int] = None

    def to_params(self) -> Dict[str, Any]:
        """
        Converts the pagination configuration to a dictionary of query parameters.

        Returns:
            Dict[str, Any]: Dictionary of parameters for HTTP request.
        """

        params: Dict[str, Any] = {}
        if self.ascending is not None:
            params["ascending"] = str(self.ascending).lower()
        if self.block_height is not None:
            params["block_height"] = self.block_height
        if self.count is not None:
            params["count"] = self.count
        return params


@dataclass(frozen=True)
class EventsPagination:
    """
    Pagination parameters for events retrival endpoint.

    Attributes:
        start_height (Optional[int]): Starting block height (inclusive).
        end_height (Optional[int]): Ending block height (exclusive).
        limit (Optional[int]): Maximum number of events to return. Defaults to 20, max 100.
        start (Optional[str]): The cursor to start the query from.
    """

    start_height: Optional[int] = None
    end_height: Optional[int] = None
    limit: Optional[int] = None
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


class TransactionType(str, Enum):
    AUTO = "auto"
    USER = "user"
    META = "meta"
