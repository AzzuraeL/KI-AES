import json
import re
import secrets
import string
import threading

SEP = "||"
MAX_LINE = 1 << 16
SESSION_KEY_LENGTH = 16

_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,16}$")
_ALPHABET = string.ascii_letters + string.digits
_print_lock = threading.Lock()


class ProtocolError(ValueError):
    pass


def valid_id(name):
    return isinstance(name, str) and bool(_ID_PATTERN.match(name))


def new_nonce():
    return secrets.randbits(32)


def f_of_n2(n2):
    return n2 + 1


def new_session_key():
    return "".join(secrets.choice(_ALPHABET) for _ in range(SESSION_KEY_LENGTH))


def is_session_key(text):
    return (isinstance(text, str) and len(text) == SESSION_KEY_LENGTH
            and text.isascii() and text.isalnum())


def pack(*parts):
    return SEP.join(parts)


def unpack(text, count):
    parts = text.split(SEP)
    if len(parts) != count:
        raise ProtocolError("malformed encrypted payload")
    return parts


def send_msg(sock, obj):
    sock.sendall(json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n")


def recv_msg(rfile):
    line = rfile.readline(MAX_LINE)
    if not line:
        return None
    if not line.endswith(b"\n"):
        raise ProtocolError("message too long or truncated")
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("message is not valid JSON")
    if not isinstance(obj, dict):
        raise ProtocolError("message must be a JSON object")
    return obj


def say(text, prompt=""):
    with _print_lock:
        if prompt:
            print("\n" + text)
            print(prompt, end="", flush=True)
        else:
            print(text, flush=True)
