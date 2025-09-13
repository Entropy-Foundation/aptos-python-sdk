# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    TRANSACTION_BY_HASH_ENDPOINT,
    TRANSACTION_ESTIMATE_GAS_PRICE_ENDPOINT,
    TRANSACTION_PARAMETERS_ENDPOINT,
    TRANSACTION_SIMULATE_TRANSACTION_ENDPOINT,
    TRANSACTION_SUBMIT_TRANSACTION_ENDPOINT,
)


class TransactionRestClient(RestClient):
    """A class that provides methods to invoke `Transaction` REST endpoints from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def transaction_by_hash(self, tx_hash: str) -> dict[str, Any]:
        """Retrieves detail of a transaction by given transaction hash.

        Args:
            tx_hash (str): The hash of the transaction.

        Returns:
           dict[str, Any]: Detail of a transaction by given transaction hash.

        """
        endpoint = TRANSACTION_BY_HASH_ENDPOINT.format(hash=tx_hash)
        return (await self.api_client.get(endpoint=endpoint)).json()

    async def estimate_gas_price(self) -> dict[str, Any]:
        """Provides statistics derived from the gas prices of recently executed transactions.

        Returns:
            dict[str, Any]: Statistics derived from the gas prices of recently executed transactions.

        """
        return (
            await self.api_client.get(endpoint=TRANSACTION_ESTIMATE_GAS_PRICE_ENDPOINT)
        ).json()

    async def transaction_parameters(self) -> dict[str, Any]:
        """Retrieve limits that a client must respect when composing a transaction.

        Returns:
            dict[str, Any]: limits that a client must respect when composing a transaction.

        """
        return (
            await self.api_client.get(endpoint=TRANSACTION_PARAMETERS_ENDPOINT)
        ).json()

    async def submit(
        self,
        transaction: bytes | dict[str, Any],
    ) -> str:
        """Submits a given transaction to the Supra network.

        Args:
            transaction (bytes | dict[str, Any]): Transaction object to submit transaction.

        Returns:
            str: Transaction hash of the submitted transaction.

        """
        headers = (
            {"Content-Type": "application/x.supra.signed_transaction+bcs"}
            if isinstance(transaction, bytes)
            else {"Content-Type": "application/json"}
        )
        response = await self.api_client.post(
            endpoint=TRANSACTION_SUBMIT_TRANSACTION_ENDPOINT,
            data=transaction,
            headers=headers,
        )
        return response.json()

    async def simulate(
        self,
        transaction: bytes | dict[str, Any],
    ) -> dict[str, Any]:
        """Simulates a given transaction.

        Args:
            transaction (bytes | dict[str, Any]):  Transaction object for simulation process.

        Returns:
            dict[str, Any]: Transaction simulation result.

        """
        headers = (
            {"Content-Type": "application/x.supra.signed_transaction+bcs"}
            if isinstance(transaction, bytes)
            else {"Content-Type": "application/json"}
        )
        response = await self.api_client.post(
            endpoint=TRANSACTION_SIMULATE_TRANSACTION_ENDPOINT,
            data=transaction,
            headers=headers,
        )
        return response.json()
