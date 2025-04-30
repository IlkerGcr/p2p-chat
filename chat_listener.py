import socket
import json
import os
from dh import calculate_shared_key, generate_public_key, PRIME
from cryptography.fernet import Fernet
import base64
import hashlib
from datetime import datetime
import secrets

TCP_PORT = 6001
CHAT_LOG_DIR = "chat_logs"

os.makedirs(CHAT_LOG_DIR, exist_ok=True)


def get_username_from_ip(ip, peer_file="peers.txt"):
    try:
        with open(peer_file, "r") as f:
            for line in f:
                saved_ip, name, _ = line.strip().split(",")
                if saved_ip == ip:
                    return name
    except FileNotFoundError:
        return None
    return None


def save_to_log(ip, msg, sent=False):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(CHAT_LOG_DIR, f"{ip}.log")
    with open(log_file, "a") as f:
        prefix = "Me" if sent else (get_username_from_ip(ip) or ip)
        f.write(f"[{now}] {prefix}: {msg}\n")


def handle_client(conn, addr):
    try:
        # Read the very first JSON packet
        data = conn.recv(2048).decode()
        if not data:
            return
        msg_json = json.loads(data)
        username = get_username_from_ip(addr[0]) or addr[0]

        # 1) Handle unsecure one-off message immediately
        if "unencrypted_message" in msg_json:
            text = msg_json["unencrypted_message"]
            print(f"[Unsecure] {username}: {text}")
            save_to_log(addr[0], text, sent=False)
            return  # close connection after handling

        # 2) Otherwise, expect a DH key handshake
        if "key" in msg_json:
            their_pub_key = int(msg_json["key"])
            private_number = secrets.randbelow(PRIME - 2) + 2
            my_pub_key = generate_public_key(private_number)
            conn.sendall(json.dumps({"key": str(my_pub_key)}).encode())

            shared_secret = calculate_shared_key(their_pub_key, private_number)
            print(f"[SecureChat] Shared key: {shared_secret}")
            key_bytes = hashlib.sha256(str(shared_secret).encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
            cipher = Fernet(fernet_key)
        else:
            print(f"[Error] Unknown initial message from {username}")
            return

        # 3) Loop to receive all encrypted messages until the client closes
        while True:
            chunk = conn.recv(2048)
            if not chunk:
                break
            packet = json.loads(chunk.decode())

            if "encrypted_message" in packet:
                decrypted = cipher.decrypt(packet["encrypted_message"].encode()).decode()
                print(f"[Secure]   {username}: {decrypted}")
                save_to_log(addr[0], decrypted, sent=False)
            else:
                print(f"[Error] Unexpected packet from {username}: {packet}")

    except Exception as e:
        print(f"[Error] Failed to handle client {addr[0]}: {e}")
    finally:
        conn.close()


def start_chat_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', TCP_PORT))
        s.listen()
        print(f"[ChatListener] Listening for TCP on port {TCP_PORT}...")
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


