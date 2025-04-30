import threading
import os
import time
from serviceAnnouncer import announce_presence
from peerDiscovery import start_peer_discovery_thread
from chat_listener import start_chat_listener
from chat_initiator import start_chat_by_username
from datetime import datetime

PEER_FILE = "peers.txt"


def load_peers():
    peers = {}
    try:
        with open(PEER_FILE, "r") as f:
            for line in f:
                ip, name, last_seen = line.strip().split(",")
                peers[ip] = (name, last_seen)
    except FileNotFoundError:
        pass
    return peers


def show_users():
    peers = load_peers()
    now = datetime.now()
    print("\nDiscovered Users:")
    for ip, (name, last_seen) in peers.items():
        try:
            last_seen_time = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            diff = (now - last_seen_time).total_seconds()
            if diff <= 10:
                status = "Online"
            elif diff <= 900:
                status = "Away"
            else:
                continue
            print(f"- {name} ({status})")
        except Exception:
            continue
    print()


def show_history():
    CHAT_LOG_DIR = "chat_logs"
    if not os.path.exists(CHAT_LOG_DIR):
        print("\nNo chat history found.\n")
        return

    peers = load_peers()
    usernames = list({name for _, (name, _) in peers.items()})

    if not usernames:
        print("\nNo known users to show history for.\n")
        return

    print("\nUsers with known chat history:")
    for name in usernames:
        print(f"- {name}")

    target_username = input("Enter the username to view history with: ").strip()
    if not target_username:
        print("[Error] Username cannot be empty.")
        return

    target_ip = None
    for ip, (name, _) in peers.items():
        if name == target_username:
            target_ip = ip
            break

    if not target_ip:
        print(f"[Error] No history found for user '{target_username}'.")
        return

    log_path = os.path.join(CHAT_LOG_DIR, f"{target_ip}.log")
    if not os.path.exists(log_path):
        print(f"[Error] No chat log file found for {target_username}.")
        return

    print(f"\nChat History with {target_username} ({target_ip}):")
    try:
        with open(log_path, "r") as f:
            for line in f:
                # Parse lines of format: [YYYY-MM-DD HH:MM:SS] Prefix: message
                if line.startswith("[") and "]" in line:
                    timestamp = line[1:20]
                    rest = line.split("] ", 1)[1]
                    prefix, msg = rest.split(": ", 1)
                    direction = "Sent" if prefix == "Me" else "Received"  ## Yazı Kısmı
                    print(f"[{timestamp}] |{target_ip}| from {prefix} ({direction}): {msg.strip()}")
                else:
                    print(line.strip())
    except Exception as e:
        print(f"[Error] Could not read chat log: {e}")
    print()


def print_help():
    print("\nAvailable commands:")
    print("  Users    - Show online and away users")
    print("  Chat     - Start a secure or unsecure chat")
    print("  History  - View chat history")
    print("  Help     - Show this help menu")
    print("  Exit     - Quit the program\n")


def main():
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    threading.Thread(target=announce_presence, args=(username,), daemon=True).start()
    start_peer_discovery_thread()
    threading.Thread(target=start_chat_listener, daemon=True).start()

    time.sleep(1)
    print("\nWelcome to P2P LAN Chat!")
    print_help()

    while True: # Main loop for command input
        try:
            cmd = input("Command > ").strip().lower()
            if cmd == "users":
                show_users()

            elif cmd == "chat":
                # Show available users before asking who to chat with
                show_users()
                target_name = input("Enter the username to chat with: ").strip()
                if not target_name:
                    print("[Error] Username cannot be empty.")
                    continue
                mode = input("Secure chat? (yes/no): ").strip().lower()
                secure = mode.startswith("y")
                start_chat_by_username(target_name, secure)

            elif cmd == "history":
                show_history()

            elif cmd == "help":
                print_help()

            elif cmd == "exit":
                print("Goodbye!")
                break

            else:
                print("[Error] Unknown command. Type 'help' for options.")

        except KeyboardInterrupt:
            print("\n[Interrupted] Use 'exit' to quit.")
        except Exception as e:
            print(f"[Error] {e}")


if __name__ == "__main__":
    main()
