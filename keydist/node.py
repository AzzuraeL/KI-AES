import argparse
import socket
import threading

from . import caesar
from .aes import decrypt_text, encrypt_text, prepare_key
from .protocol import (ProtocolError, f_of_n2, is_session_key, new_nonce, recv_msg,
                       say, send_msg, unpack, valid_id)

HANDSHAKE_TIMEOUT = 10

HELP = """commands:
  connect <peer> <host>:<port>   run key distribution (steps 1-5) with a peer
  send <peer> <message>          send an AES-encrypted message
  sessions                       list established sessions
  close <peer>                   close a session
  key                            show my Caesar key (shared with the KDC)
  setkey <shift>                 change my Caesar key
  kdc <host>:<port>              change KDC address
  help | quit"""


def _expect(msg, kind):
    if msg is None:
        raise ProtocolError("connection closed by remote side")
    if msg.get("type") == "ERROR":
        raise ProtocolError("remote error: " + str(msg.get("reason", "unknown")))
    if msg.get("type") != kind:
        raise ProtocolError(f"expected {kind}, got {msg.get('type')}")
    return msg


def local_ip_towards(host, port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, port))
        return probe.getsockname()[0]
    except OSError:
        return "unknown"
    finally:
        probe.close()


class Session:
    def __init__(self, peer, sock, rfile, ks_text):
        self.peer = peer
        self.sock = sock
        self.rfile = rfile
        self.ks_text = ks_text
        self.key = prepare_key(ks_text)
        self.send_lock = threading.Lock()

    def send(self, obj):
        with self.send_lock:
            send_msg(self.sock, obj)

    def close(self):
        try:
            self.send({"type": "BYE"})
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class Node:
    def __init__(self, name, key_text, kdc_addr, log=None):
        if not valid_id(name):
            raise ValueError("name must be 1-16 chars of A-Z a-z 0-9 _ -")
        self.name = name
        self.key_text = key_text
        self.shift = caesar.parse_shift(key_text)
        self.kdc_addr = kdc_addr
        self.sessions = {}
        self.lock = threading.Lock()
        self.server = None
        self.busy = False
        self.log = log or self._console_log

    def _console_log(self, text):
        say(text, "" if self.busy else f"{self.name}> ")

    def set_key(self, key_text):
        shift = caesar.parse_shift(key_text)
        self.key_text = key_text
        self.shift = shift

    def listen(self, host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(8)
        self.server = server
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return server.getsockname()[1]

    def shutdown(self):
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.close()
        if self.server:
            self.server.close()

    def connect(self, peer, host, port):
        if not valid_id(peer) or peer == self.name:
            raise ProtocolError("invalid peer identity")
        n1 = new_nonce()
        ks_text, ticket = self._ask_kdc(peer, n1)
        ks = prepare_key(ks_text)

        sock = socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT)
        try:
            rfile = sock.makefile("rb")
            send_msg(sock, {"step": 3, "type": "TICKET", "ticket": ticket})
            self.log(f"[STEP 3] {self.name} -> {peer} : E(Kb,[Ks||IDA]) = {ticket}")
            challenge = _expect(recv_msg(rfile), "CHALLENGE")
            try:
                n2 = int(decrypt_text(ks, challenge.get("enc_n2")))
            except ValueError:
                raise ProtocolError("challenge cannot be decrypted with Ks")
            self.log(f"[STEP 4] {peer} -> {self.name} : E(Ks,N2) = {challenge['enc_n2']}\n"
                     f"         decrypted N2={n2}")
            answer = encrypt_text(ks, str(f_of_n2(n2)))
            send_msg(sock, {"step": 5, "type": "RESPONSE", "enc_fn2": answer})
            self.log(f"[STEP 5] {self.name} -> {peer} : E(Ks,f(N2)) = {answer}\n"
                     f"         f(N2)={f_of_n2(n2)}")
            _expect(recv_msg(rfile), "HANDSHAKE_OK")
        except (OSError, ValueError):
            sock.close()
            raise
        sock.settimeout(None)
        session = Session(peer, sock, rfile, ks_text)
        self._register(session)
        threading.Thread(target=self._read_loop, args=(session,), daemon=True).start()
        self.log(f"session with {peer} established, Ks={ks_text}")
        return session

    def send_text(self, peer, text):
        with self.lock:
            session = self.sessions.get(peer)
        if session is None:
            raise ProtocolError(f"no session with {peer}, use connect first")
        cipher = encrypt_text(session.key, text)
        try:
            session.send({"type": "MSG", "from": self.name, "cipher": cipher})
        except OSError:
            self._drop(session)
            raise
        self.log(f"[SENT to {peer}]\n"
                 f"   plaintext  : {text}\n"
                 f"   key (Ks)   : {session.ks_text}\n"
                 f"   ciphertext : {cipher}")

    def close_session(self, peer):
        with self.lock:
            session = self.sessions.pop(peer, None)
        if session is None:
            raise ProtocolError(f"no session with {peer}")
        session.close()

    def _ask_kdc(self, peer, n1):
        request = {"step": 1, "type": "KEY_REQUEST",
                   "id_a": self.name, "id_b": peer, "n1": str(n1)}
        self.log(f"[STEP 1] {self.name} -> KDC : IDA={self.name} IDB={peer} N1={n1}")
        with socket.create_connection(self.kdc_addr, timeout=HANDSHAKE_TIMEOUT) as sock:
            send_msg(sock, request)
            reply = _expect(recv_msg(sock.makefile("rb")), "KEY_RESPONSE")
        try:
            ks, id_a, id_b, nonce = unpack(caesar.decrypt(self.shift, reply.get("enc_a")), 4)
        except ValueError:
            raise ProtocolError("KDC reply cannot be decrypted with my key "
                                "(is Ka the same as at the KDC?)")
        if not is_session_key(ks) or (id_a, id_b, nonce) != (self.name, peer, str(n1)):
            raise ProtocolError("KDC reply does not match my request "
                                "(is Ka the same as at the KDC?)")
        ticket = reply.get("ticket")
        if not isinstance(ticket, str):
            raise ProtocolError("KDC reply has no ticket")
        self.log(f"[STEP 2] KDC -> {self.name} : E(Ka,[Ks||IDA||IDB||N1]) = {reply['enc_a']}\n"
                 f"         decrypted: Ks={ks} IDA={id_a} IDB={id_b} N1={nonce} (all match)")
        return ks, ticket

    def _register(self, session):
        with self.lock:
            old = self.sessions.get(session.peer)
            self.sessions[session.peer] = session
        if old:
            old.close()

    def _drop(self, session):
        with self.lock:
            if self.sessions.get(session.peer) is session:
                del self.sessions[session.peer]
        session.close()

    def _accept_loop(self):
        while True:
            try:
                conn, addr = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn, addr):
        conn.settimeout(HANDSHAKE_TIMEOUT)
        try:
            session = self._respond(conn, addr)
        except (OSError, ValueError) as exc:
            self.log(f"handshake from {addr[0]}:{addr[1]} failed: {exc}")
            try:
                send_msg(conn, {"type": "ERROR", "reason": str(exc)})
            except OSError:
                pass
            conn.close()
            return
        conn.settimeout(None)
        self._read_loop(session)

    def _respond(self, conn, addr):
        rfile = conn.makefile("rb")
        msg = _expect(recv_msg(rfile), "TICKET")
        ticket = msg.get("ticket")
        try:
            ks_text, id_a = unpack(caesar.decrypt(self.shift, ticket), 2)
            if not (is_session_key(ks_text) and valid_id(id_a)):
                raise ProtocolError("bad content in ticket")
        except ValueError:
            raise ProtocolError("ticket cannot be decrypted with my key "
                                "(is Kb the same as at the KDC?)")
        ks = prepare_key(ks_text)
        self.log(f"[STEP 3] {id_a} -> {self.name} : E(Kb,[Ks||IDA]) = {ticket}\n"
                 f"         decrypted: Ks={ks_text} IDA={id_a}")

        n2 = new_nonce()
        enc_n2 = encrypt_text(ks, str(n2))
        send_msg(conn, {"step": 4, "type": "CHALLENGE", "enc_n2": enc_n2})
        self.log(f"[STEP 4] {self.name} -> {id_a} : E(Ks,N2) = {enc_n2}\n"
                 f"         N2={n2}")

        reply = _expect(recv_msg(rfile), "RESPONSE")
        try:
            answer = decrypt_text(ks, reply.get("enc_fn2"))
        except ValueError:
            raise ProtocolError("response cannot be decrypted with Ks")
        self.log(f"[STEP 5] {id_a} -> {self.name} : E(Ks,f(N2)) = {reply['enc_fn2']}\n"
                 f"         decrypted: {answer}, expected {f_of_n2(n2)}")
        if answer != str(f_of_n2(n2)):
            raise ProtocolError("f(N2) mismatch, authentication failed")

        send_msg(conn, {"type": "HANDSHAKE_OK"})
        session = Session(id_a, conn, rfile, ks_text)
        self._register(session)
        self.log(f"session with {id_a} established, Ks={ks_text}")
        return session

    def _read_loop(self, session):
        while True:
            try:
                msg = recv_msg(session.rfile)
            except (OSError, ValueError):
                break
            if msg is None or msg.get("type") == "BYE":
                break
            if msg.get("type") != "MSG":
                continue
            cipher = msg.get("cipher")
            try:
                plain = decrypt_text(session.key, cipher)
            except ValueError as exc:
                self.log(f"[RECEIVED from {session.peer}] decryption failed: {exc}\n"
                         f"   ciphertext : {cipher}")
                continue
            self.log(f"[RECEIVED from {session.peer}]\n"
                     f"   ciphertext : {cipher}\n"
                     f"   key (Ks)   : {session.ks_text}\n"
                     f"   plaintext  : {plain}")
        with self.lock:
            current = self.sessions.get(session.peer) is session
        self._drop(session)
        if current:
            self.log(f"session with {session.peer} closed")


def parse_addr(text):
    host, sep, port = text.rpartition(":")
    if not sep or not host:
        raise ValueError("address must look like host:port")
    return host, int(port)


def run_command(node, line):
    cmd, _, rest = line.partition(" ")
    cmd = cmd.lower()
    rest = rest.strip()
    if cmd in ("quit", "exit"):
        return False
    if cmd == "help":
        say(HELP)
    elif cmd == "connect":
        args = rest.split()
        if len(args) != 2:
            raise ValueError("usage: connect <peer> <host>:<port>")
        host, port = parse_addr(args[1])
        node.connect(args[0], host, port)
    elif cmd == "send":
        args = rest.split(None, 1)
        if len(args) != 2:
            raise ValueError("usage: send <peer> <message>")
        node.send_text(args[0], args[1])
    elif cmd == "sessions":
        with node.lock:
            if not node.sessions:
                say("(no sessions)")
            for peer, session in node.sessions.items():
                say(f"  {peer:<16} Ks={session.ks_text}")
    elif cmd == "close":
        node.close_session(rest)
        say(f"session with {rest} closed")
    elif cmd == "key":
        say(f"Caesar key (shift): {node.shift}")
    elif cmd == "setkey":
        node.set_key(rest)
        say(f"Caesar key changed (shift: {node.shift})")
    elif cmd == "kdc":
        node.kdc_addr = parse_addr(rest)
        say(f"KDC set to {rest}")
    elif cmd:
        say("unknown command, type 'help'")
    return True


def repl(node):
    say(HELP)
    while True:
        try:
            line = input(f"{node.name}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        node.busy = True
        try:
            if not run_command(node, line):
                break
        except (OSError, ValueError) as exc:
            say("error: " + str(exc))
        finally:
            node.busy = False
    node.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Alice / Bob node")
    parser.add_argument("--name", required=True)
    parser.add_argument("--key", help="Caesar shift shared with the KDC (prompted if omitted)")
    parser.add_argument("--kdc", default="127.0.0.1:5000", metavar="HOST:PORT")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=6001)
    args = parser.parse_args()

    key_text = args.key if args.key is not None else input("Caesar key, integer (same as at KDC): ")
    try:
        kdc_addr = parse_addr(args.kdc)
        node = Node(args.name, key_text, kdc_addr)
        port = node.listen(args.listen_host, args.listen_port)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    say(f"{node.name} listening on {args.listen_host}:{port}")
    say(f"my IP towards KDC: {local_ip_towards(*kdc_addr)}")
    repl(node)


if __name__ == "__main__":
    main()
