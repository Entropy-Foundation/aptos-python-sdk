# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    COMMITTEE_AUTHORIZATION_ENDPOINT,
    CONSENSUS_BLOCK_BY_HEIGHT_ENDPOINT,
    LATEST_CONSENSUS_BLOCK_ENDPOINT,
)


class ConsensusRestClient(RestClient):
    """A class that provides methods to invoke `Consensus` REST endpoints from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def latest_consensus_block(self) -> bytes:
        """Retrieves the BCS bytes of the latest consensus block.

        Returns:
             bytes: BCS bytes of the latest consensus block.

        """
        self.api_client.api_client_config.raise_if_access_token_not_exists()
        return (
            await self.api_client.get(endpoint=LATEST_CONSENSUS_BLOCK_ENDPOINT)
        ).read()

    async def consensus_block_by_height(
        self, height: int, with_batches: bool = False
    ) -> bytes:
        """Retrieves the BCS bytes of the consensus block at the requested height.

        Args:
            height (int): The height of the consensus block to retrieve.
            with_batches (bool): If true, returns all batches of transactions with certificates contained in this block.
                Default to False.

        Returns:
            bytes: BCS bytes of the consensus block at the requested height.

        """
        self.api_client.api_client_config.raise_if_access_token_not_exists()
        endpoint = CONSENSUS_BLOCK_BY_HEIGHT_ENDPOINT.format(height=height)
        params = {"with_batches": str(with_batches).lower()}
        return (await self.api_client.get(endpoint=endpoint, params=params)).read()

    async def committee_authorization(self, epoch: int) -> bytes:
        """Retrieves the BCS bytes of the Committee Authorization for the given epoch.

        Args:
            epoch (int): The epoch number.

        Returns:
            bytes: BCS bytes of the Committee Authorization for the requested epoch.

        """
        self.api_client.api_client_config.raise_if_access_token_not_exists()
        endpoint = COMMITTEE_AUTHORIZATION_ENDPOINT.format(epoch=epoch)
        return (await self.api_client.get(endpoint=endpoint)).read()
