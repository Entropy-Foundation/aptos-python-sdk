# Copyright © Supra
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from supra_sdk.account_address import AccountAddress
from supra_sdk.clients.rest.rest_client import RestClient
from supra_sdk.clients.rest.rest_types import (
    FAUCET_ENDPOINT,
    FAUCET_TRANSACTION_ENDPOINT,
)


class FaucetRestClient(RestClient):
    """A class that provides methods to invoke `Faucet` REST endpoints from a Supra RPC node.

    Attributes:
        api_client (ApiClient): Inherited from `RestClient`. Used to send HTTP requests to the Supra RPC node.

    """

    async def fund_with_faucet(self, address: AccountAddress) -> str | None:
        """Requests faucet funds to be sent to the given account address.

        Args:
            address (AccountAddress): The target account address to receive funds.

        Returns:
            str | None: Faucet transaction hash if faucet request is accepted else None.

        """
        endpoint = FAUCET_ENDPOINT.format(address=address)
        res_data = (await self.api_client.get(endpoint=endpoint)).json()
        return res_data.get("Accepted", None)

    async def faucet_transaction_by_hash(self, tx_hash: str) -> dict[str, Any]:
        """Retrieves details of a faucet transaction by its hash.

        Args:
            tx_hash (str): The hash of the faucet transaction.

        Returns:
            dict[str, Any]: Faucet transaction details.

        """
        endpoint = FAUCET_TRANSACTION_ENDPOINT.format(hash=tx_hash)
        return (await self.api_client.get(endpoint=endpoint)).json()
