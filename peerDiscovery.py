
import socket
import json
from datetime import datetime
import threading
import time

PORT = 6000
PEER_FILE = "peers.txt"
STATUS = {}   # track current status per IP


def load_peers():
    peers = {}
    try:
        with open(PEER_FILE, "r") as f:
            for line in f:
                ip, username, last_seen = line.strip().split(",")
                peers[ip] = (username, last_seen)
    except FileNotFoundError:
        pass
    return peers


def save_peers(peers):
    with open(PEER_FILE, "w") as f:
        for ip, (username, last_seen) in peers.items():
            f.write(f"{ip},{username},{last_seen}\n")


def peer_discovery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    print("[PeerDiscovery] Listening for broadcasts on port 6000...")
    peers = load_peers()

    # background thread to print status changes
    def monitor():
        while True:
            now = datetime.now()
            for ip, (username, last_seen) in peers.items():
                then = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                delta = (now - then).total_seconds()
                new_status = "Online" if delta <= 10 else "Away" if delta <= 900 else None
                old = STATUS.get(ip)
                if new_status and new_status != old:
                    STATUS[ip] = new_status
                    verb = "back online" if new_status == "Online" else "away"
                    print(f"[PeerDiscovery] {username} is {verb}")
            time.sleep(5)

    threading.Thread(target=monitor, daemon=True).start()

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            ip = addr[0]
            try:
                message = json.loads(data.decode())
                username = message.get("username")
                if not username:
                    continue

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                is_new = ip not in peers

                peers[ip] = (username, timestamp)
                save_peers(peers)

                if is_new:
                    print(f"[PeerDiscovery] {username} is online")

            except json.JSONDecodeError:
                print(f"[PeerDiscovery] Invalid JSON from {ip}")
        except Exception as e:
            print(f"[PeerDiscovery] Error: {e}")


def start_peer_discovery_thread():
    t = threading.Thread(target=peer_discovery, daemon=True)
    t.start()


if __name__ == "__main__":
    peer_discovery()
