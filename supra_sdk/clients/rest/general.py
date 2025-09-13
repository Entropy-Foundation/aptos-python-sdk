# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    CHAIN_ID_ENDPOINT,
    EVENTS_BY_TYPE_ENDPOINT,
    TABLE_ITEMS_ENDPOINT,
    VIEW_FUNCTION_ENDPOINT,
    EventsPagination,
)


class GeneralRestClient(RestClient):
    """A class that provides convenient methods to interact with general REST endpoints like `View`, `table` and `Event`
    from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def network_chain_id(self):
        """Provides the network Chain-ID.

        Returns:
            int: Network Chain-ID.

        """
        return int((await self.api_client.get(endpoint=CHAIN_ID_ENDPOINT)).text)

    async def view(
        self,
        function: str,
        type_arguments: list[str],
        arguments: list[str],
    ) -> list[Any]:
        """Execute a view Move function with the given parameters and return its execution result.

        Args:
            function (str): Entry function id is string representation of an entry function defined on-chain.
            type_arguments (list[str]): Type arguments of the function.
            arguments (list[str]): Arguments of the function.

        Returns:
            list[Any]: Execution results of the view function.

        """
        data = {
            "function": function,
            "type_arguments": type_arguments,
            "arguments": arguments,
        }
        res_data = (
            await self.api_client.post(endpoint=VIEW_FUNCTION_ENDPOINT, data=data)
        ).json()
        return res_data["result"]

    async def get_table_item(
        self,
        table_handle: str,
        key_type: str,
        value_type: str,
        key: Any,
    ) -> dict[str, Any]:
        """Retrieves an item from a table by key.

        Args:
            table_handle (str): Table handle to lookup. Should be retrieved using account resources API.
            key_type (str): The type of the table key.
            value_type (str): The type of the table value.
            key (str): The key to fetch from the table.

        Returns:
            dict[str, Any]: Item associated with the key in the table.

        """
        endpoint = TABLE_ITEMS_ENDPOINT.format(table_handle=table_handle)
        data = {
            "key_type": key_type,
            "value_type": value_type,
            "key": key,
        }
        return (await self.api_client.post(endpoint=endpoint, data=data)).json()

    async def events_by_type(
        self, event_type: str, pagination: EventsPagination | None = None
    ) -> tuple[list[dict[str, Any]], str]:
        """Retrieves events of a given type.

        Args:
            event_type (str): The fully qualified name of the event struct e.g. '0x1::coin::CoinDeposit'.
            pagination (EventsPagination | None): Pagination options. Default to None.

        Returns:
            tuple[list[dict[str, Any]], str]: A tuple containing,
                - list[dict[str, Any]]: List of events.
                - str: Cursor to retrieve the next page.

        """
        endpoint = EVENTS_BY_TYPE_ENDPOINT.format(event_type=event_type)
        params = pagination.to_params() if pagination else {}
        response = await self.api_client.get(endpoint=endpoint, params=params)
        return response.json()["data"], response.headers.get("x-supra-cursor", "")
