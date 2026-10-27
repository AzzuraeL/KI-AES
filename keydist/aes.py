import os
import sys

BLOCK_SIZE = 16


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def _gmul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _build_sbox():
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inverse[a] = b
                break
    sbox = []
    for value in inverse:
        x = value
        out = value
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            out ^= x
        sbox.append(out ^ 0x63)
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

_MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}
_M2, _M3, _M9, _M11, _M13, _M14 = (_MUL[n] for n in (2, 3, 9, 11, 13, 14))


def _expand_key(key):
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def _add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def _sub_bytes(state):
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def _shift_rows(state):
    return [state[(i + 4 * (i % 4)) % 16] for i in range(16)]


def _inv_shift_rows(state):
    return [state[(i - 4 * (i % 4)) % 16] for i in range(16)]


def _mix_columns(state):
    out = []
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out += [
            _M2[a0] ^ _M3[a1] ^ a2 ^ a3,
            a0 ^ _M2[a1] ^ _M3[a2] ^ a3,
            a0 ^ a1 ^ _M2[a2] ^ _M3[a3],
            _M3[a0] ^ a1 ^ a2 ^ _M2[a3],
        ]
    return out


def _inv_mix_columns(state):
    out = []
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out += [
            _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
            _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
            _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
            _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3],
        ]
    return out


class AES:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.rounds = len(key) // 4 + 6
        self.round_keys = _expand_key(bytes(key))

    def encrypt_block(self, block):
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must be 16 bytes")
        keys = self.round_keys
        state = _add_round_key(list(block), keys[0])
        for r in range(1, self.rounds):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _mix_columns(state)
            state = _add_round_key(state, keys[r])
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _add_round_key(state, keys[self.rounds])
        return bytes(state)

    def decrypt_block(self, block):
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must be 16 bytes")
        keys = self.round_keys
        state = _add_round_key(list(block), keys[self.rounds])
        for r in range(self.rounds - 1, 0, -1):
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
            state = _add_round_key(state, keys[r])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, keys[0])
        return bytes(state)


def pkcs7_pad(data):
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("invalid padded length")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid padding")
    return data[:-n]


def encrypt_cbc(key, plaintext, iv=None):
    cipher = AES(key)
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    padded = pkcs7_pad(plaintext)
    previous = iv
    out = [iv]
    for i in range(0, len(padded), BLOCK_SIZE):
        mixed = bytes(a ^ b for a, b in zip(padded[i:i + BLOCK_SIZE], previous))
        previous = cipher.encrypt_block(mixed)
        out.append(previous)
    return b"".join(out)


def decrypt_cbc(key, data):
    if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("ciphertext length invalid")
    cipher = AES(key)
    previous = data[:BLOCK_SIZE]
    out = []
    for i in range(BLOCK_SIZE, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        plain = cipher.decrypt_block(block)
        out.append(bytes(a ^ b for a, b in zip(plain, previous)))
        previous = block
    return pkcs7_unpad(b"".join(out))


def prepare_key(text):
    try:
        raw = text.encode("ascii")
    except (UnicodeEncodeError, AttributeError):
        raise ValueError("key must be an ASCII string")
    if not raw:
        raise ValueError("key must not be empty")
    if len(raw) > 32:
        raise ValueError("key must be at most 32 characters")
    for size in (16, 24, 32):
        if len(raw) <= size:
            return raw.ljust(size, b"\x00")


def encrypt_text(key, text, iv=None):
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("plaintext must be ASCII")
    return encrypt_cbc(key, data, iv).hex()


def decrypt_text(key, hex_text):
    if not isinstance(hex_text, str):
        raise ValueError("ciphertext must be a hex string")
    try:
        data = bytes.fromhex(hex_text)
        return decrypt_cbc(key, data).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("decrypted data is not ASCII (wrong key?)")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    usage = "usage: python -m keydist.aes enc KEY TEXT [IV_HEX] | dec KEY CIPHER_HEX"
    if len(argv) < 3 or argv[0] not in ("enc", "dec"):
        print(usage)
        return 1
    try:
        key = prepare_key(argv[1])
        print("key bytes :", key.hex())
        if argv[0] == "enc":
            iv = bytes.fromhex(argv[3]) if len(argv) > 3 else None
            print("ciphertext:", encrypt_text(key, argv[2], iv))
        else:
            print("plaintext :", decrypt_text(key, argv[2]))
    except ValueError as exc:
        print("error:", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
