import socket
import threading
import time
import unittest

from keydist.kdc import KDC
from keydist.node import Node
from keydist.protocol import ProtocolError, is_session_key, recv_msg, send_msg


def loopback(index):
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.%d" % index, 0))
        return "127.0.0.%d" % index
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def wait_for(predicate, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class Env:
    def __init__(self, alice_key="7", bob_key="13"):
        self.kdc_host, self.alice_host, self.bob_host = loopback(1), loopback(2), loopback(3)
        self.kdc_log, self.alice_log, self.bob_log = [], [], []
        self.kdc = KDC(log=self.kdc_log.append)
        self.kdc.set_key("alice", "7")
        self.kdc.set_key("bob", "13")
        kdc_port = self.kdc.listen(self.kdc_host, 0)
        kdc_addr = (self.kdc_host, kdc_port)
        self.alice = Node("alice", alice_key, kdc_addr, log=self.alice_log.append)
        self.bob = Node("bob", bob_key, kdc_addr, log=self.bob_log.append)
        self.alice_port = self.alice.listen(self.alice_host, 0)
        self.bob_port = self.bob.listen(self.bob_host, 0)

    def close(self):
        self.alice.shutdown()
        self.bob.shutdown()
        self.kdc.close()


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()

    def tearDown(self):
        self.env.close()

    def test_handshake_and_two_way_messages(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        self.assertTrue(wait_for(lambda: "alice" in env.bob.sessions))
        self.assertEqual(env.alice.sessions["bob"].ks_text, env.bob.sessions["alice"].ks_text)

        env.alice.send_text("bob", "halo bob")
        self.assertTrue(wait_for(lambda: any("plaintext  : halo bob" in m for m in env.bob_log)))
        env.bob.send_text("alice", "halo alice")
        self.assertTrue(wait_for(lambda: any("plaintext  : halo alice" in m for m in env.alice_log)))

    def test_bob_can_initiate(self):
        env = self.env
        env.bob.connect("alice", env.alice_host, env.alice_port)
        self.assertTrue(wait_for(lambda: "bob" in env.alice.sessions))
        env.alice.send_text("bob", "reply over bob's session")
        self.assertTrue(wait_for(lambda: any("reply over bob's session" in m for m in env.bob_log)))

    def test_new_connect_issues_new_session_key(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        first = env.alice.sessions["bob"].ks_text
        env.alice.connect("bob", env.bob_host, env.bob_port)
        self.assertNotEqual(first, env.alice.sessions["bob"].ks_text)
        env.alice.send_text("bob", "after rekey")
        self.assertTrue(wait_for(lambda: any("after rekey" in m for m in env.bob_log)))

    def test_wrong_initiator_key(self):
        env = self.env
        env.alice.set_key("29")
        with self.assertRaises(ProtocolError):
            env.alice.connect("bob", env.bob_host, env.bob_port)

    def test_wrong_responder_key(self):
        env = self.env
        env.bob.set_key("29")
        with self.assertRaises(ProtocolError):
            env.alice.connect("bob", env.bob_host, env.bob_port)
        self.assertNotIn("bob", env.alice.sessions)

    def test_key_change_on_both_sides(self):
        env = self.env
        env.kdc.set_key("alice", "42")
        env.alice.set_key("42")
        env.alice.connect("bob", env.bob_host, env.bob_port)

    def test_unknown_identity(self):
        env = self.env
        with self.assertRaises(ProtocolError):
            env.alice.connect("carol", env.bob_host, env.bob_port)

    def test_send_without_session(self):
        with self.assertRaises(ProtocolError):
            self.env.alice.send_text("bob", "x")

    def test_non_ascii_message_rejected(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        with self.assertRaises(ValueError):
            env.alice.send_text("bob", "caf\u00e9")

    def test_setks_changes_key_on_live_session(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        old = env.alice.sessions["bob"].ks_text
        custom = "KsKustom12345678"
        env.alice.set_session_key("bob", custom)
        self.assertTrue(wait_for(lambda: env.bob.sessions["alice"].ks_text == custom))
        self.assertEqual(env.alice.sessions["bob"].ks_text, custom)
        self.assertNotEqual(custom, old)
        env.alice.send_text("bob", "pesan key baru")
        self.assertTrue(wait_for(lambda: any("plaintext  : pesan key baru" in m for m in env.bob_log)))
        env.bob.send_text("alice", "balas key baru")
        self.assertTrue(wait_for(lambda: any("plaintext  : balas key baru" in m for m in env.alice_log)))

    def test_setks_random_and_rejects_bad_key(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        old = env.alice.sessions["bob"].ks_text
        new = env.alice.set_session_key("bob")
        self.assertTrue(is_session_key(new))
        self.assertNotEqual(new, old)
        self.assertTrue(wait_for(lambda: env.bob.sessions["alice"].ks_text == new))
        with self.assertRaises(ValueError):
            env.alice.set_session_key("bob", "pendek")

    def test_replayed_ticket_without_ks_fails(self):
        env = self.env
        env.alice.connect("bob", env.bob_host, env.bob_port)
        ticket = next(m for m in env.alice_log if m.startswith("[STEP 3]")).split("= ")[1].strip()
        attacker = socket.create_connection((env.bob_host, env.bob_port), timeout=3)
        rfile = attacker.makefile("rb")
        send_msg(attacker, {"type": "TICKET", "ticket": ticket})
        self.assertEqual(recv_msg(rfile)["type"], "CHALLENGE")
        send_msg(attacker, {"type": "RESPONSE", "enc_fn2": "00" * 32})
        self.assertEqual(recv_msg(rfile)["type"], "ERROR")
        attacker.close()

    def test_tampered_reply_from_kdc_detected(self):
        env = self.env
        original = env.kdc.issue

        def tampered(request):
            reply = original(request)
            reply["enc_a"] = reply["enc_a"][:-2] + ("00" if reply["enc_a"][-2:] != "00" else "01")
            return reply

        env.kdc.issue = tampered
        with self.assertRaises(ProtocolError):
            env.alice.connect("bob", env.bob_host, env.bob_port)

    def test_garbage_to_kdc_and_node(self):
        env = self.env
        for addr in ((env.kdc_host, env.kdc.server.getsockname()[1]), (env.bob_host, env.bob_port)):
            sock = socket.create_connection(addr, timeout=3)
            sock.sendall(b"not json at all\n")
            sock.settimeout(3)
            try:
                data = sock.recv(4096)
            except OSError:
                data = b""
            sock.close()
            self.assertTrue(data == b"" or b"ERROR" in data)


if __name__ == "__main__":
    unittest.main()
