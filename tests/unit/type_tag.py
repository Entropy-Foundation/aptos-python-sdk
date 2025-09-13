# Copyright © Supra
# Parts of the project are originally copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest

from supra_sdk.type_tag import StructTag


class Test(unittest.TestCase):
    def test_nested_structs(self):
        l0 = "0x0::l0::L0"
        l10 = "0x1::l10::L10"
        l20 = "0x2::l20::L20"
        l11 = "0x1::l11::L11"
        composite = f"{l0}<{l10}<{l20}>, {l11}>"
        derived = StructTag.from_str(composite)
        self.assertEqual(composite, f"{derived}")
        in_bytes = derived.to_bytes()
        from_bytes = StructTag.from_bytes(in_bytes)
        self.assertEqual(derived, from_bytes)
