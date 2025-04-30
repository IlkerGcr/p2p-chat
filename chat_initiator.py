import socket
import json
import os
from datetime import datetime
from dh import generate_public_key, calculate_shared_key  # Diffie-Hellman key exchange
from cryptography.fernet import Fernet  # For encryption
import base64
import hashlib

TCP_PORT = 6001
CHAT_LOG_DIR = "chat_logs"
PEER_FILE = "peers.txt"

os.makedirs(CHAT_LOG_DIR, exist_ok=True)  # Ensure chat log folder exists


# Save messages to per-peer log files
def save_to_log(ip, msg, sent=True):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(CHAT_LOG_DIR, f"{ip}.log")
    with open(log_file, "a") as f:
        prefix = "Me" if sent else ip
        f.write(f"[{now}] {prefix}: {msg}\n")


# Read peers.txt and return the IP of a username
def get_ip_from_username(username, peer_file=PEER_FILE):
    try:
        with open(peer_file, "r") as f:
            for line in f:
                ip, name, _ = line.strip().split(",")
                if name == username:
                    return ip
    except FileNotFoundError:
        print("[Error] Peer list not found.")
    return None


# Send unsecure message over TCP
def send_unsecure_chat(ip):
    print("Enter messages below. Type 'exit' to stop chatting.")
    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            break
        if not msg.strip():
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, TCP_PORT))
                json_message = json.dumps({ "unencrypted_message": msg })  # Use JSON key
                s.sendall(json_message.encode())
                save_to_log(ip, msg)
        except Exception as e:
            print(f"[Error] Could not send message to {ip}: {e}")


# Send a secure message after performing DH key exchange
def send_secure_chat(ip):
    try:
        private_number = int(input("Enter your private number: "))
    except ValueError:
        print("Invalid number.")
        return

    public_key = generate_public_key(private_number)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, TCP_PORT))
            # Step 1: send own public key
            s.sendall(json.dumps({ "key": str(public_key) }).encode())

            # Step 2: receive peer's public key
            peer_data = s.recv(1024)
            peer_json = json.loads(peer_data.decode())
            peer_key = int(peer_json["key"])

            # Step 3: calculate shared secret
            shared_secret = calculate_shared_key(peer_key, private_number)
            print(f"[SecureChat] Shared key: {shared_secret}")

            # Step 4: convert shared secret to a Fernet key
            key_bytes = hashlib.sha256(str(shared_secret).encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
            cipher = Fernet(fernet_key)

            # Step 5: send encrypted messages
            print("Enter messages below. Type 'exit' to stop chatting.")
            while True:
                msg = input("You: ")
                if msg.lower() == "exit":
                    break
                if not msg.strip():
                    continue
                encrypted = cipher.encrypt(msg.encode())
                s.sendall(json.dumps({ "encrypted_message": encrypted.decode() }).encode())
                save_to_log(ip, msg)
    except Exception as e:
        print(f"[Error] Secure chat failed: {e}")


# General-purpose chat starter
def start_chat(ip, secure):
    if secure:
        send_secure_chat(ip)
    else:
        send_unsecure_chat(ip)


# starts chat by using a username (uses peer list to get IP)
def start_chat_by_username(username, secure, peer_file=PEER_FILE):
    ip = get_ip_from_username(username, peer_file)
    if ip:
        start_chat(ip, secure)
    else:
        print(f"[Error] User '{username}' not found in peer list.")
