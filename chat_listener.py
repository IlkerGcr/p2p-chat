import socket
import json
import os
import base64
import hashlib
import secrets
import pyDes
from datetime import datetime
from dh import calculate_shared_key, generate_public_key, PRIME

TCP_PORT = 6001
CHAT_LOG_DIR = "chat_logs"
os.makedirs(CHAT_LOG_DIR, exist_ok=True)

# keep shared secrets by peer IP
shared_secrets: dict[str, int] = {}


def get_username_from_ip(ip: str, peer_file: str = "peers.txt") -> str | None:
    try:
        with open(peer_file, "r") as f:
            for line in f:
                saved_ip, name, _ = line.strip().split(",", 2)
                if saved_ip == ip:
                    return name
    except FileNotFoundError:
        pass
    return None


def save_to_log(ip: str, msg: str, sent: bool = False):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fn = os.path.join(CHAT_LOG_DIR, f"{ip}.log")
    prefix = "Me" if sent else ip
    with open(fn, "a") as f:
        f.write(f"[{now}] {prefix}: {msg}\n")


def handle_client(conn: socket.socket, addr):
    ip = addr[0]
    try:
        raw = conn.recv(2048)
        if not raw:
            return
        pkt = json.loads(raw.decode())
        user = get_username_from_ip(ip) or ip

        # A) Plaintext chat
        if "unencrypted_message" in pkt:
            txt = pkt["unencrypted_message"]
            print(f"[Unsecure] {user}: {txt}")
            save_to_log(ip, txt, sent=False)
            return

        # B) Reconnect-only encrypted blob
        if "encrypted_message" in pkt:
            if ip not in shared_secrets:
                print(f"[Error] No shared key for {user}.")
                return

            ct = base64.b64decode(pkt["encrypted_message"])
            secret = shared_secrets[ip]
            wowkey = str(secret).ljust(24)
            cipher = pyDes.triple_des(wowkey, padmode=pyDes.PAD_PKCS5)
            pt = cipher.decrypt(ct).decode('utf-8')

            print(f"[Secure] {user}: {pt}")
            save_to_log(ip, pt, sent=False)
            return

        # C) DH handshake + one encrypted message
        if "key" in pkt:
            their_pub = int(pkt["key"])
            # respond
            priv = secrets.randbelow(PRIME - 2) + 2
            my_pub = generate_public_key(priv)
            conn.sendall(json.dumps({"key": str(my_pub)}).encode())

            # compute & remember secret
            secret = calculate_shared_key(their_pub, priv)
            shared_secrets[ip] = secret

            # receive one encrypted_message
            raw2 = conn.recv(2048)
            if not raw2:
                print(f"[SecureChat] No payload from {user}.")
                return
            pkt2 = json.loads(raw2.decode())

            if "encrypted_message" in pkt2:
                ct2 = base64.b64decode(pkt2["encrypted_message"])
                wowkey = str(secret).ljust(24)
                cipher2 = pyDes.triple_des(wowkey, padmode=pyDes.PAD_PKCS5)
                pt2 = cipher2.decrypt(ct2).decode()

                print(f"[Secure] {user}: {pt2}")
                save_to_log(ip, pt2, sent=False)
            else:
                print(f"[Error] Unexpected after handshake: {pkt2}")
            return

        # D) Unknown packet
        print(f"[Error] Unknown packet from {user}: {pkt}")

    except Exception as e:
        print(f"[Error] Failed to handle {ip}: {e}")
    finally:
        conn.close()


def start_chat_listener():
    """
    Imported by main.py: bind to TCP_PORT and handle one message per conn.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(('', TCP_PORT))
        srv.listen()
        print(f"[ChatListener] Listening on port {TCP_PORT}…")
        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr)


