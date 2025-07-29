# Copyright © Supra Foundation
# SPDX-License-Identifier: Apache-2.0

import os
import os.path

SUPRA_CORE_PATH = os.getenv(
    "SUPRA_CORE_PATH",
    os.path.abspath("./supra-core"),
)
# :!:>section_1
FAUCET_URL = os.getenv(
    "SUPRA_FAUCET_URL",
    "https://rpc-testnet.supra.com",
)
NODE_URL = os.getenv("SUPRA_NODE_URL", "https://rpc-testnet.supra.com")
# <:!:section_1
