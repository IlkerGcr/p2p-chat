import socket
import json
import os
import base64
import secrets
from datetime import datetime

import pyDes
from dh import generate_public_key, calculate_shared_key, PRIME

TCP_PORT = 6001
CHAT_LOG_DIR = "chat_logs"
PEER_FILE = "peers.txt"

# Ensure the log directory exists
os.makedirs(CHAT_LOG_DIR, exist_ok=True)


def save_to_log(ip: str, msg: str, sent: bool = True):
    """Append a timestamped entry to chat_logs/<ip>.log."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(CHAT_LOG_DIR, f"{ip}.log")
    prefix = "Me" if sent else ip
    with open(path, "a") as f:
        f.write(f"[{now}] {prefix}: {msg}\n")


def get_ip_from_username(username: str, peer_file: str = PEER_FILE) -> str | None:
    """Look up an IP address for a given username in peers.txt."""
    try:
        with open(peer_file, "r") as f:
            for line in f:
                ip, name, _ = line.strip().split(",", 2)
                if name == username:
                    return ip
    except FileNotFoundError:
        pass
    return None


def send_unsecure_chat(ip: str):
    """Send exactly one plaintext JSON message, then close."""
    msg = input("Enter unsecure message: ").strip()
    if not msg:
        print("[Unsecure] No message entered.")
        return

    packet = json.dumps({"unencrypted_message": msg}).encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, TCP_PORT))
            s.sendall(packet)
        save_to_log(ip, msg, sent=True)
        print("[Unsecure] Message sent.")
    except Exception as e:
        print(f"[Error] Could not send unsecure to {ip}: {e}")


def send_secure_chat(ip: str):
    """Perform DH, derive 3DES key (PyDes), send one encrypted JSON, then close."""
    # 1) Ask for our DH private exponent
    try:
        priv = int(input("Enter your DH private number: "))
    except ValueError:
        print("[Secure] Invalid number.")
        return

    # 2) Generate and send our DH public key
    pub = generate_public_key(priv)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, TCP_PORT))

            # send { "key": "<our_pub>" }
            s.sendall(json.dumps({"key": str(pub)}).encode())

            # receive { "key": "<their_pub>" }
            resp = s.recv(2048)
            their_pub = int(json.loads(resp.decode())["key"])

            # compute shared secret
            secret = calculate_shared_key(their_pub, priv)
            print(f"[Secure] Shared secret: {secret}")

            # derive a 24-byte key string (left-justified, pad with spaces)
            wowkey = str(secret).ljust(24)

            # 3) Prompt for exactly one message
            msg = input("Enter secure message: ").strip()
            if not msg:
                print("[Secure] No message entered.")
                return

            # 4) Encrypt with PyDes.triple_des + PAD_PKCS5 (padmode=2)
            cipher = pyDes.triple_des(wowkey, padmode=pyDes.PAD_PKCS5)
            raw_ct = cipher.encrypt(msg.encode('utf-8'))

            # 5) Base64-encode the raw ciphertext so it’s JSON-safe
            blob = base64.b64encode(raw_ct).decode()

            # 6) Send single JSON field { "encrypted_message": blob }
            s.sendall(json.dumps({"encrypted_message": blob}).encode())
            save_to_log(ip, msg, sent=True)
            print("[Secure] Message sent. Connection closed.")

    except Exception as e:
        print(f"[Error] Secure chat failed: {e}")


def start_chat(ip: str, secure: bool):
    """Dispatch to secure or unsecure send and then exit."""
    if secure:
        send_secure_chat(ip)
    else:
        send_unsecure_chat(ip)


def start_chat_by_username(username: str, secure: bool):
    """
    Entry point for main.py:
      1. Lookup IP in peers.txt by username
      2. Call send_secure_chat or send_unsecure_chat
    """
    ip = get_ip_from_username(username)
    if not ip:
        print(f"[Error] User '{username}' not found in peer list.")
        return
    start_chat(ip, secure)
