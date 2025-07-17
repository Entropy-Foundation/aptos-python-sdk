# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Provides a test harness for treating examples as integration tests.
"""

import asyncio
import os
import unittest
from typing import Optional

from supra_sdk.account_address import AccountAddress
from supra_sdk.supra_cli_wrapper import SupraCLIWrapper, SupraInstance

from .common import SUPRA_CORE_PATH


class Test(unittest.IsolatedAsyncioTestCase):
    _node: Optional[SupraInstance] = None

    @classmethod
    def setUpClass(self):
        if os.getenv("SUPRA_TEST_USE_EXISTING_NETWORK"):
            return

        self._node = SupraCLIWrapper.start_node()
        operational = asyncio.run(self._node.wait_until_operational())
        if not operational:
            raise Exception("".join(self._node.errors()))

        os.environ["SUPRA_FAUCET_URL"] = "http://127.0.0.1:27001"
        os.environ["SUPRA_NODE_URL"] = "http://127.0.0.1:27000"

    async def test_supra_token(self):
        from . import supra_token

        await supra_token.main()

    async def test_fee_payer_transfer_coin(self):
        from . import fee_payer_transfer_coin

        await fee_payer_transfer_coin.main()

    async def test_hello_blockchain(self):
        from . import hello_blockchain

        hello_blockchain_dir = os.path.join(
            SUPRA_CORE_PATH, "supra-move", "move-examples", "hello_blockchain"
        )
        SupraCLIWrapper.test_package(
            hello_blockchain_dir, {"hello_blockchain": AccountAddress.from_str("0xa")}
        )
        contract_address = await hello_blockchain.publish_contract(hello_blockchain_dir)
        await hello_blockchain.main(contract_address)

    async def test_large_package_publisher(self):
        # TODO -- this is currently broken, out of gas
        return

        from . import large_package_publisher

        large_packages_dir = os.path.join(
            SUPRA_CORE_PATH, "supra-move", "move-examples", "large_packages"
        )
        module_addr = await large_package_publisher.publish_large_packages(
            large_packages_dir
        )
        large_package_example_dir = os.path.join(
            large_packages_dir, "large_package_example"
        )
        await large_package_publisher.main(large_package_example_dir, module_addr)

    async def test_multisig(self):
        from . import multisig

        await multisig.main(False)

    async def test_read_aggreagtor(self):
        from . import read_aggregator

        await read_aggregator.main()

    async def test_rotate_key(self):
        from . import rotate_key

        await rotate_key.main()

    async def test_secp256k1_ecdsa_transfer_coin(self):
        from . import secp256k1_ecdsa_transfer_coin

        await secp256k1_ecdsa_transfer_coin.main()

    async def test_simple_supra_token(self):
        from . import simple_supra_token

        await simple_supra_token.main()

    async def test_simple_nft(self):
        from . import simple_nft

        await simple_nft.main()

    async def test_simulate_transfer_coin(self):
        from . import simulate_transfer_coin

        await simulate_transfer_coin.main()

    async def test_transfer_coin(self):
        from . import transfer_coin

        await transfer_coin.main()

    async def test_transfer_two_by_two(self):
        from . import transfer_two_by_two

        await transfer_two_by_two.main()

    async def test_your_coin(self):
        from . import your_coin

        moon_coin_path = os.path.join(
            SUPRA_CORE_PATH, "supra-move", "move-examples", "moon_coin"
        )
        SupraCLIWrapper.test_package(
            moon_coin_path, {"MoonCoin": AccountAddress.from_str("0xa")}
        )
        await your_coin.main(moon_coin_path)

    @classmethod
    def tearDownClass(self):
        if os.getenv("SUPRA_TEST_USE_EXISTING_NETWORK"):
            return

        self._node.stop()


if __name__ == "__main__":
    unittest.main(buffer=True)
