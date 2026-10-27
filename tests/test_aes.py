import unittest

from keydist import aes


def h(text):
    return bytes.fromhex(text)


class BlockTests(unittest.TestCase):
    def test_sbox_samples(self):
        self.assertEqual(aes.SBOX[0x00], 0x63)
        self.assertEqual(aes.SBOX[0x53], 0xED)
        self.assertEqual(aes.SBOX[0xFF], 0x16)
        self.assertEqual(aes.INV_SBOX[0x63], 0x00)

    def test_fips197_appendix_b(self):
        cipher = aes.AES(h("2b7e151628aed2a6abf7158809cf4f3c"))
        plain = h("3243f6a8885a308d313198a2e0370734")
        expected = h("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(cipher.encrypt_block(plain), expected)
        self.assertEqual(cipher.decrypt_block(expected), plain)

    def test_fips197_appendix_c(self):
        plain = h("00112233445566778899aabbccddeeff")
        cases = [
            ("000102030405060708090a0b0c0d0e0f",
             "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617",
             "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for key, expected in cases:
            cipher = aes.AES(h(key))
            self.assertEqual(cipher.encrypt_block(plain), h(expected))
            self.assertEqual(cipher.decrypt_block(h(expected)), plain)

    def test_bad_sizes(self):
        with self.assertRaises(ValueError):
            aes.AES(b"short")
        with self.assertRaises(ValueError):
            aes.AES(bytes(16)).encrypt_block(b"abc")


class CbcTests(unittest.TestCase):
    def test_sp800_38a_first_block(self):
        key = h("2b7e151628aed2a6abf7158809cf4f3c")
        iv = h("000102030405060708090a0b0c0d0e0f")
        out = aes.encrypt_cbc(key, h("6bc1bee22e409f96e93d7e117393172a"), iv)
        self.assertEqual(out[:16], iv)
        self.assertEqual(out[16:32], h("7649abac8119b246cee98e9b12e9197d"))

    def test_roundtrip_lengths(self):
        for size in (16, 24, 32):
            key = bytes(range(size))
            for n in (0, 1, 15, 16, 17, 31, 32, 100):
                data = bytes((i * 7) % 256 for i in range(n))
                self.assertEqual(aes.decrypt_cbc(key, aes.encrypt_cbc(key, data)), data)

    def test_random_iv_changes_output(self):
        key = bytes(16)
        self.assertNotEqual(aes.encrypt_cbc(key, b"same"), aes.encrypt_cbc(key, b"same"))

    def test_padding_errors(self):
        for bad in (b"", b"\x00" * 15, b"\x00" * 16, b"a" * 15 + b"\x11", b"a" * 14 + b"\x01\x02"):
            with self.assertRaises(ValueError):
                aes.pkcs7_unpad(bad)

    def test_tampered_length_rejected(self):
        key = bytes(16)
        with self.assertRaises(ValueError):
            aes.decrypt_cbc(key, b"\x00" * 31)
        with self.assertRaises(ValueError):
            aes.decrypt_cbc(key, b"\x00" * 16)


class TextTests(unittest.TestCase):
    def test_prepare_key_padding(self):
        self.assertEqual(aes.prepare_key("a" * 16), b"a" * 16)
        self.assertEqual(aes.prepare_key("abc"), b"abc" + bytes(13))
        self.assertEqual(len(aes.prepare_key("a" * 17)), 24)
        self.assertEqual(len(aes.prepare_key("a" * 25)), 32)

    def test_prepare_key_rejects(self):
        for bad in ("", "a" * 33, "k\u00e9y"):
            with self.assertRaises(ValueError):
                aes.prepare_key(bad)

    def test_text_roundtrip_and_hex(self):
        key = aes.prepare_key("Kunci-Rahasia-123")
        cipher = aes.encrypt_text(key, "Halo Bob, ini pesan rahasia!")
        int(cipher, 16)
        self.assertEqual(aes.decrypt_text(key, cipher), "Halo Bob, ini pesan rahasia!")

    def test_non_ascii_plaintext_rejected(self):
        with self.assertRaises(ValueError):
            aes.encrypt_text(bytes(16), "caf\u00e9")

    def test_wrong_key_fails(self):
        good = aes.prepare_key("right-key")
        cipher = aes.encrypt_text(good, "secret message", bytes(16))
        failures = 0
        for i in range(50):
            try:
                aes.decrypt_text(aes.prepare_key("wrong-key-%d" % i), cipher)
            except ValueError:
                failures += 1
        self.assertGreaterEqual(failures, 48)

    def test_bad_hex(self):
        with self.assertRaises(ValueError):
            aes.decrypt_text(bytes(16), "zz")
        with self.assertRaises(ValueError):
            aes.decrypt_text(bytes(16), None)


if __name__ == "__main__":
    unittest.main()
