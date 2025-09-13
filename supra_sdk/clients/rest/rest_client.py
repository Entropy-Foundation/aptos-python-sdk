# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from supra_sdk.clients import ApiClient


class RestClient:
    """A base class for building category-specific REST API clients.

    This class provides a shared interface and a common `api_client` instance for sending REST API requests. Other REST
    client classes can inherit from `RestClient` to reuse this functionality.

    Attributes:
        api_client (ApiClient): The API client instance used to perform HTTP requests against the REST API.

    """

    api_client: ApiClient

    def __init__(self, api_client: ApiClient):
        """Initialize a `RestClient` instance.

        Args:
            api_client (ApiClient): An instance of `ApiClient` responsible for managing HTTP requests.

        """
        self.api_client = api_client
