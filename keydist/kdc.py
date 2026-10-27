import argparse
import socket
import threading

from . import caesar
from .protocol import (ProtocolError, new_session_key, pack, recv_msg, say,
                       send_msg, valid_id)

REQUEST_TIMEOUT = 10

HELP = """commands:
  keys [show]          list registered identities (show = reveal keys)
  setkey <id> <shift>  register or change the Caesar key (integer) of an identity
  delkey <id>          remove an identity
  help                 this text
  quit                 stop the KDC"""


class KDC:
    def __init__(self, log=say):
        self.log = log
        self.keys = {}
        self.raw_keys = {}
        self.lock = threading.Lock()
        self.server = None

    def set_key(self, ident, key_text):
        if not valid_id(ident):
            raise ValueError("identity must be 1-16 chars of A-Z a-z 0-9 _ -")
        shift = caesar.parse_shift(key_text)
        with self.lock:
            self.keys[ident] = shift
            self.raw_keys[ident] = key_text

    def del_key(self, ident):
        with self.lock:
            if ident not in self.keys:
                raise ValueError("unknown identity: " + ident)
            del self.keys[ident]
            del self.raw_keys[ident]

    def issue(self, request):
        if request.get("type") != "KEY_REQUEST":
            raise ProtocolError("expected KEY_REQUEST")
        id_a, id_b, n1 = request.get("id_a"), request.get("id_b"), request.get("n1")
        if not (valid_id(id_a) and valid_id(id_b)):
            raise ProtocolError("invalid identity")
        if not (isinstance(n1, str) and n1.isascii() and n1.isdigit()):
            raise ProtocolError("invalid nonce")
        if id_a == id_b:
            raise ProtocolError("initiator and responder must differ")
        with self.lock:
            ka = self.keys.get(id_a)
            kb = self.keys.get(id_b)
        for ident, key in ((id_a, ka), (id_b, kb)):
            if key is None:
                raise ProtocolError("unknown identity: " + ident)

        self.log(f"[STEP 1] {id_a} -> KDC : IDA={id_a} IDB={id_b} N1={n1}")
        ks = new_session_key()
        enc_a = caesar.encrypt(ka, pack(ks, id_a, id_b, n1))
        ticket = caesar.encrypt(kb, pack(ks, id_a))
        self.log(f"[STEP 2] KDC -> {id_a} : generated Ks={ks}\n"
                 f"         E(Ka,[Ks||IDA||IDB||N1]) = {enc_a}\n"
                 f"         E(Kb,[Ks||IDA])          = {ticket}")
        return {"step": 2, "type": "KEY_RESPONSE", "enc_a": enc_a, "ticket": ticket}

    def listen(self, host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(16)
        self.server = server
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return server.getsockname()[1]

    def close(self):
        if self.server:
            self.server.close()

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        conn.settimeout(REQUEST_TIMEOUT)
        try:
            request = recv_msg(conn.makefile("rb"))
            if request is None:
                return
            try:
                reply = self.issue(request)
            except ProtocolError as exc:
                self.log(f"[REJECT] {addr[0]}:{addr[1]} -> {exc}")
                reply = {"type": "ERROR", "reason": str(exc)}
            send_msg(conn, reply)
        except (OSError, ProtocolError) as exc:
            self.log(f"[ERROR] {addr[0]}:{addr[1]} -> {exc}")
        finally:
            conn.close()


def console(kdc):
    say(HELP)
    while True:
        try:
            line = input("kdc> ").strip()
        except KeyboardInterrupt:
            return True
        except EOFError:
            return False
        cmd, _, rest = line.partition(" ")
        rest = rest.strip()
        try:
            if cmd in ("quit", "exit"):
                return True
            elif cmd == "help":
                say(HELP)
            elif cmd == "keys":
                with kdc.lock:
                    if not kdc.keys:
                        say("(no identities registered)")
                    for ident, raw in kdc.raw_keys.items():
                        shown = raw if rest == "show" else "*" * len(raw)
                        say(f"  {ident:<16} {shown}")
            elif cmd == "setkey":
                ident, _, key = rest.partition(" ")
                if not key:
                    raise ValueError("usage: setkey <id> <shift>")
                kdc.set_key(ident, key)
                say(f"key for {ident} updated")
            elif cmd == "delkey":
                kdc.del_key(rest)
                say(f"{rest} removed")
            elif cmd:
                say("unknown command, type 'help'")
        except ValueError as exc:
            say("error: " + str(exc))


def main():
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--key", action="append", default=[], metavar="ID=SHIFT",
                        help="register an identity at startup (repeatable)")
    args = parser.parse_args()

    kdc = KDC()
    for item in args.key:
        ident, sep, key = item.partition("=")
        if not sep:
            parser.error("--key expects ID=SHIFT")
        try:
            kdc.set_key(ident, key)
        except ValueError as exc:
            parser.error(str(exc))

    port = kdc.listen(args.host, args.port)
    say(f"KDC listening on {args.host}:{port}")
    if not kdc.keys:
        say("no identities yet, use: setkey <id> <shift>")
    if not console(kdc):
        threading.Event().wait()
    kdc.close()


if __name__ == "__main__":
    main()
