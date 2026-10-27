LOW = 32
HIGH = 126
SIZE = HIGH - LOW + 1


def parse_shift(text):
    if not isinstance(text, str):
        raise ValueError("Caesar key must be an integer")
    text = text.strip()
    digits = text[1:] if text[:1] in "+-" else text
    if not (text.isascii() and digits.isdigit()):
        raise ValueError("Caesar key must be an integer, e.g. 7")
    shift = int(text) % SIZE
    if shift == 0:
        raise ValueError("Caesar key must not be a multiple of %d" % SIZE)
    return shift


def _rotate(text, shift):
    out = []
    for ch in text:
        code = ord(ch)
        if not LOW <= code <= HIGH:
            raise ValueError("character outside printable ASCII")
        out.append(chr((code - LOW + shift) % SIZE + LOW))
    return "".join(out)


def encrypt(shift, text):
    return _rotate(text, shift).encode("ascii").hex()


def decrypt(shift, hex_text):
    if not isinstance(hex_text, str):
        raise ValueError("ciphertext must be a hex string")
    try:
        text = bytes.fromhex(hex_text).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("ciphertext is not ASCII")
    return _rotate(text, -shift)
