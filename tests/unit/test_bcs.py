# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0


from __future__ import annotations

import unittest

from supra_sdk.bcs import Deserializer, Serializer


class Test(unittest.TestCase):
    def test_bool_true(self):
        in_value = True

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_false(self):
        in_value = False

        ser = Serializer()
        ser.bool(in_value)
        der = Deserializer(ser.output())
        out_value = der.bool()

        self.assertEqual(in_value, out_value)

    def test_bool_error(self):
        ser = Serializer()
        ser.u8(32)
        der = Deserializer(ser.output())
        with self.assertRaises(Exception):
            der.bool()

    def test_bytes(self):
        in_value = b"1234567890"

        ser = Serializer()
        ser.to_bytes(in_value)
        der = Deserializer(ser.output())
        out_value = der.to_bytes()

        self.assertEqual(in_value, out_value)

    def test_map(self):
        in_value = {"a": 12345, "b": 99234, "c": 23829}

        ser = Serializer()
        ser.map(in_value, Serializer.str, Serializer.u32)
        der = Deserializer(ser.output())
        out_value = der.map(Deserializer.str, Deserializer.u32)

        self.assertEqual(in_value, out_value)

    def test_sequence(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        ser.sequence(in_value, Serializer.str)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_sequence_serializer(self):
        in_value = ["a", "abc", "def", "ghi"]

        ser = Serializer()
        seq_ser = Serializer.sequence_serializer(Serializer.str)
        seq_ser(ser, in_value)
        der = Deserializer(ser.output())
        out_value = der.sequence(Deserializer.str)

        self.assertEqual(in_value, out_value)

    def test_str(self):
        in_value = "1234567890"

        ser = Serializer()
        ser.str(in_value)
        der = Deserializer(ser.output())
        out_value = der.str()

        self.assertEqual(in_value, out_value)

    def test_u8(self):
        in_value = 15

        ser = Serializer()
        ser.u8(in_value)
        der = Deserializer(ser.output())
        out_value = der.u8()

        self.assertEqual(in_value, out_value)

    def test_u16(self):
        in_value = 11115

        ser = Serializer()
        ser.u16(in_value)
        der = Deserializer(ser.output())
        out_value = der.u16()

        self.assertEqual(in_value, out_value)

    def test_u32(self):
        in_value = 1111111115

        ser = Serializer()
        ser.u32(in_value)
        der = Deserializer(ser.output())
        out_value = der.u32()

        self.assertEqual(in_value, out_value)

    def test_u64(self):
        in_value = 1111111111111111115

        ser = Serializer()
        ser.u64(in_value)
        der = Deserializer(ser.output())
        out_value = der.u64()

        self.assertEqual(in_value, out_value)

    def test_u128(self):
        in_value = 1111111111111111111111111111111111115

        ser = Serializer()
        ser.u128(in_value)
        der = Deserializer(ser.output())
        out_value = der.u128()

        self.assertEqual(in_value, out_value)

    def test_u256(self):
        in_value = 111111111111111111111111111111111111111111111111111111111111111111111111111115

        ser = Serializer()
        ser.u256(in_value)
        der = Deserializer(ser.output())
        out_value = der.u256()

        self.assertEqual(in_value, out_value)

    def test_uleb128(self):
        in_value = 1111111115

        ser = Serializer()
        ser.uleb128(in_value)
        der = Deserializer(ser.output())
        out_value = der.uleb128()

        self.assertEqual(in_value, out_value)


if __name__ == "__main__":
    unittest.main()
