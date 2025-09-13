# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import os

SUPRA_CORE_PATH = os.getenv("SUPRA_CORE_PATH", os.path.abspath("../aptos-core"))
FAUCET_URL = os.getenv(
    "SUPRA_FAUCET_URL",
    "http://localhost:27001/",
)
RPC_NODE_URL = os.getenv("SUPRA_RPC_NODE_URL", "http://localhost:27001/")
