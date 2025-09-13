# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from supra_sdk.account_address import AccountAddress
from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    ACCOUNT_AUTOMATED_TRANSACTIONS_ENDPOINT,
    ACCOUNT_COIN_TRANSACTIONS_ENDPOINT,
    ACCOUNT_ENDPOINT,
    ACCOUNT_MODULE_ENDPOINT,
    ACCOUNT_MODULES_ENDPOINT,
    ACCOUNT_RESOURCE_ENDPOINT,
    ACCOUNT_RESOURCES_ENDPOINT,
    ACCOUNT_TRANSACTIONS_ENDPOINT,
    AutomatedTransactionsPagination,
    Pagination,
    PaginationWithOrder,
)


class AccountRestClient(RestClient):
    """A class that provides methods to invoke `Account` REST endpoints from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def account(
        self,
        account_address: AccountAddress,
    ) -> dict[str, str]:
        """Provides the authentication key and the sequence number of the given account.

        Args:
            account_address (AccountAddress): Address of the account.

        Returns:
            dict[str, str]: The authentication key and sequence number of the given account.

        """
        endpoint = ACCOUNT_ENDPOINT.format(account_address=account_address)
        return (await self.api_client.get(endpoint=endpoint)).json()

    async def account_resource(
        self,
        account_address: AccountAddress,
        resource_type: str,
    ) -> dict[str, Any]:
        """Retrieves an individual resource from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            resource_type (str): Type of the resource e.g. '0x1::account::Account'.

        Returns:
            dict[str, Any]: An individual resource from a given account.

        """
        endpoint = ACCOUNT_RESOURCE_ENDPOINT.format(
            account_address=account_address, resource_type=resource_type
        )
        return (await self.api_client.get(endpoint=endpoint)).json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        pagination: Pagination | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Retrieves all account resources for a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Pagination | None): Pagination options. Default to None.

        Returns:
            tuple[list[dict[str, Any]], str]: A tuple containing,
                - list[dict[str, Any]]: All account resources for a given account.
                - str: Cursor to retrieve the next page.

        """
        endpoint = ACCOUNT_RESOURCES_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        response = await self.api_client.get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_module(
        self,
        account_address: AccountAddress,
        module_name: str,
    ) -> dict[str, Any]:
        """Retrieves an individual module from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            module_name (str): Name of the module to retrieve e.g. 'account'

        Returns:
            dict[str, Any]: An individual module from a given account.

        """
        endpoint = ACCOUNT_MODULE_ENDPOINT.format(
            account_address=account_address, module_name=module_name
        )
        return (await self.api_client.get(endpoint=endpoint)).json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        pagination: Pagination | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Retrieves all account modules from a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (Pagination | None): Pagination options. Default to None.

        Returns:
            tuple[list[dict[str, Any]], str]: A tuple containing,
                - list[dict[str, Any]]: All account modules from a given account.
                - str: Cursor to retrieve the next page.

        """
        endpoint = ACCOUNT_MODULES_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        response = await self.api_client.get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_transactions(
        self,
        account_address: AccountAddress,
        pagination: PaginationWithOrder | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieves details of finalized transactions sent by a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (PaginationWithOrder | None): Pagination options. Default to None.
                Note: Sequence number would be used as start in pagination option.

        Returns:
            list[dict[str, Any]]: Details of finalized transactions sent by a given account.

        """
        endpoint = ACCOUNT_TRANSACTIONS_ENDPOINT.format(account_address=account_address)
        params = pagination.to_params() if pagination else {}
        return (await self.api_client.get(endpoint=endpoint, params=params)).json()

    async def account_coin_transactions(
        self,
        account_address: AccountAddress,
        pagination: PaginationWithOrder | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Retrieves details of finalized coin deposit/withdraw type transactions associated with a given account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (PaginationWithOrder | None): Pagination options. Default to None.

        Returns:
            tuple[list[dict[str, Any]], str]: A tuple containing,
                - list[dict[str, Any]]: Details of finalized coin deposit/withdraw type transactions associated with a
                    given account.
                - str: Cursor to retrieve the next page.

        """
        endpoint = ACCOUNT_COIN_TRANSACTIONS_ENDPOINT.format(
            account_address=account_address
        )
        params = pagination.to_params() if pagination else {}
        response = await self.api_client.get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")

    async def account_automated_transactions(
        self,
        account_address: AccountAddress,
        pagination: AutomatedTransactionsPagination | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Retrieves details of finalized automated transactions based on the automation tasks registered by a given
            account.

        Args:
            account_address (AccountAddress): Address of the account.
            pagination (AutomatedTransactionsPagination | None): Pagination options. Default to None.

        Returns:
            tuple[list[dict[str, Any]], str]: A tuple containing,
                - list[dict[str, Any]]: Details of finalized automated transactions details based on the automation
                    tasks registered by a given account.
                - str: Cursor to retrieve the next page.

        """
        endpoint = ACCOUNT_AUTOMATED_TRANSACTIONS_ENDPOINT.format(
            account_address=account_address
        )
        params = pagination.to_params() if pagination else {}
        response = await self.api_client.get(endpoint=endpoint, params=params)
        return response.json(), response.headers.get("x-supra-cursor", "")
