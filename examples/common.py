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
    "http://localhost:27001",
)
NODE_URL = os.getenv("SUPRA_NODE_URL", "http://localhost:27000")
# <:!:section_1
