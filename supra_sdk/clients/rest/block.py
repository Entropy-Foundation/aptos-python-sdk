# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    BLOCK_BY_HASH_ENDPOINT,
    BLOCK_BY_HEIGHT_ENDPOINT,
    BLOCK_TRANSACTIONS_ENDPOINT,
    LATEST_BLOCK_ENDPOINT,
    TransactionType,
)


class BlockRestClient(RestClient):
    """A class that provides methods to invoke `Block` REST endpoints from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def latest_block(self) -> dict[str, Any]:
        """Retrieves the metadata information of the most recently finalized and executed block.

        Returns:
            dict[str, Any]: Metadata information of the most recently finalized and executed block.

        """
        return (await self.api_client.get(endpoint=LATEST_BLOCK_ENDPOINT)).json()

    async def block_by_hash(self, block_hash: str) -> dict[str, Any]:
        """Retrieves the header and execution output statistics of the block with the given hash.

        Args:
            block_hash (str): The hash of the block.

        Returns:
            dict[str, Any]: Header and execution output statistics of the block with the given hash.

        """
        endpoint = BLOCK_BY_HASH_ENDPOINT.format(block_hash=block_hash)
        return (await self.api_client.get(endpoint=endpoint)).json()

    async def block_by_height(
        self,
        height: int,
        transaction_type: TransactionType | None = None,
        with_finalized_transaction: bool = False,
    ) -> dict[str, Any]:
        """Retrieves information about the block that has been finalized at the given height.

        Args:
            height (int): The height of the block.
            transaction_type (TransactionType | None): Transaction type to query. If missing any/all type of
                transactions will be looked for. Default to None.
            with_finalized_transaction (bool): Whether to include finalized transactions or not. Default to False.

        Returns:
            dict[str, Any]: Information about the block that has been finalized at the given height.

        """
        endpoint = BLOCK_BY_HEIGHT_ENDPOINT.format(height=height)
        params: dict[str, str | bool] = {
            "with_finalized_transactions": with_finalized_transaction
        }
        if transaction_type:
            params["transaction_type"] = transaction_type.value
        return (await self.api_client.get(endpoint=endpoint, params=params)).json()

    async def txs_by_block(
        self, block_hash: str, transaction_type: TransactionType | None = None
    ) -> list[str]:
        """Retrieves a list containing the hashes of the transactions that were finalized in the block with the given
            hash in the order that they were executed.

        Args:
            block_hash (str): The hash of the block.
            transaction_type (TransactionType | None): Transaction type to query. If missing any/all type of
                transactions will be looked for. Default tp None

        Returns:
            list[str]: List transaction's hash that were finalized in the given block.

        """
        endpoint = BLOCK_TRANSACTIONS_ENDPOINT.format(block_hash=block_hash)
        params = (
            {"transaction_type": transaction_type.value} if transaction_type else {}
        )
        return (await self.api_client.get(endpoint=endpoint, params=params)).json()
