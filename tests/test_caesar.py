import unittest

from keydist import caesar


class CaesarTests(unittest.TestCase):
    def test_known_shift(self):
        self.assertEqual(bytes.fromhex(caesar.encrypt(3, "abc")).decode(), "def")
        self.assertEqual(bytes.fromhex(caesar.encrypt(1, "~")).decode(), " ")

    def test_roundtrip_all_printable(self):
        text = "".join(chr(c) for c in range(caesar.LOW, caesar.HIGH + 1))
        for shift in (1, 7, 50, 94):
            self.assertEqual(caesar.decrypt(shift, caesar.encrypt(shift, text)), text)

    def test_negative_and_large_keys_wrap(self):
        self.assertEqual(caesar.parse_shift("-1"), 94)
        self.assertEqual(caesar.parse_shift("100"), 5)

    def test_rejects_bad_keys(self):
        for bad in ("", "abc", "0", "95", "1.5", None):
            with self.assertRaises(ValueError):
                caesar.parse_shift(bad)

    def test_rejects_bad_data(self):
        with self.assertRaises(ValueError):
            caesar.encrypt(3, "caf\u00e9")
        with self.assertRaises(ValueError):
            caesar.encrypt(3, "line\nbreak")
        with self.assertRaises(ValueError):
            caesar.decrypt(3, "00")
        with self.assertRaises(ValueError):
            caesar.decrypt(3, "zz")
        with self.assertRaises(ValueError):
            caesar.decrypt(3, None)


if __name__ == "__main__":
    unittest.main()
