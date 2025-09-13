# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, cast
from urllib.parse import urljoin

import httpx

from supra_sdk.metadata import Metadata


@dataclass
class ApiClientConfig:
    """Holds configuration options related to the generic API client.

    Attributes:
        http2 (bool): Whether to use HTTP/2 for requests. Default to False.
        access_token (Optional[str]): Optional access token (JWT) for authentication. Default to None.

    """

    http2: bool = False
    access_token: str | None = None

    def raise_if_access_token_not_exists(self):
        """Raise an error if the access token is not set.

        Checks whether `self.access_token` exists. If it does not, an
        `AuthorizationKeyNotSpecifiedError` is raised.

        Raises:
            AuthorizationKeyNotSpecifiedError: If `self.access_token` is missing or None.

        """
        if not self.access_token:
            raise AuthorizationKeyNotSpecifiedError


class ApiClient:
    """A generic API client for making HTTP requests, it acts as a base class for specific API clients.

    Attributes:
        _client (httpx.AsyncClient): HTTP client to send the http request.
        base_url (str): The base URL of the API.
        api_client_config (ApiClientConfig): Configuration options for API client.

    """

    _client: httpx.AsyncClient
    base_url: str
    api_client_config: ApiClientConfig

    def __init__(self, base_url: str, api_client_config: ApiClientConfig | None = None):
        """Initializes the API client.

        Args:
            base_url (str): The base URL of the API.
            api_client_config (ApiClientConfig): Configuration options for API client. Default to None.

        """
        api_client_config = api_client_config or ApiClientConfig()
        self.base_url = base_url
        limits = httpx.Limits()
        timeout = httpx.Timeout(60.0, pool=None)
        headers = {Metadata.SUPRA_HEADER: Metadata.get_supra_header_val()}
        self._client = httpx.AsyncClient(
            http2=api_client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=headers,
        )
        self.api_client_config = api_client_config

    async def close(self):
        """Closes the HTTP client session."""
        await self._client.aclose()

    async def get(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        strict_mode: bool | None = True,
    ) -> httpx.Response:
        """Performs an asynchronous GET request.

        Args:
            endpoint (str): Endpoint to call.
            headers (dict[str, str] | None): Optional headers. Default to None.
            params (dict[str, Any] | None): Optional query parameters. Default to None.
            strict_mode (bool | None): If enabled then raises an error when request response status
                code is not 200. Default to True.

        Returns:
            httpx.Response: The response from the server.

        """
        params = params or {}
        params = {key: val for key, val in params.items() if val is not None}
        headers = headers or {}

        if self.api_client_config.access_token:
            headers["Authorization"] = f"Bearer {self.api_client_config.access_token}"

        response = await self._client.get(
            url=urljoin(self.base_url, endpoint), params=params, headers=headers
        )
        if strict_mode and response.status_code != HTTPStatus.OK:
            raise ApiError(response.text, response.status_code)
        return response

    async def post(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        data: dict[str, Any] | bytes | None = None,
        strict_mode: bool | None = True,
    ) -> httpx.Response:
        """Performs an asynchronous POST request.

        Args:
            endpoint (str): API endpoint.
            params (dict[str, Any] | None): Query parameters. Default to None.
            headers (dict[str, Any] | None): Request headers. Default to None.
            data (dict[str, Any] | bytes | None): POST body data. Default to None.
            strict_mode (bool | None): If enabled then raises an error when request response status code is not 200.
                Default to True.

        Returns:
            httpx.Response: The response from the server.

        """
        params = params or {}
        params = {key: val for key, val in params.items() if val is not None}
        headers = headers or {}

        content: str | bytes
        if not isinstance(data, bytes):
            headers["Content-Type"] = "application/json"
            content = json.dumps(data)
        else:
            content = cast(bytes, data)

        response = await self._client.post(
            url=urljoin(self.base_url, endpoint),
            params=params,
            headers=headers,
            content=content,
        )
        if strict_mode and response.status_code != HTTPStatus.OK:
            raise ApiError(response.text, response.status_code)
        return response


class ApiError(Exception):
    """Exception raised when the API returns a non-200 response.

    Attributes:
        status_code (int): The HTTP status code returned.

    """

    status_code: int

    def __init__(self, message: str, status_code: int):
        """Initialize the exception with message and response status code.

        Args:
            message (str): Error message.
            status_code (int): The HTTP status code returned.

        """
        self.status_code = status_code
        super().__init__(f"{{message: {message}, status_code: {status_code}}}")


class AuthorizationKeyNotSpecifiedError(Exception):
    """Exception raised when consensus api endpoints are accessed without defining `access_token` in `ClientConfig`."""

    def __init__(self):
        """Initialize the exception with a default message."""
        super().__init__("Authorization key is not specified")
