import socket
import time
import json

BROADCAST_IP = '192.168.1.255'   # As required  Normal kısım
#BROADCAST_IPS = ['25.40.156.101', '25.18.31.237']  # Add your Hamachi peer IPs here

PORT = 6000
BROADCAST_INTERVAL = 8.0

def announce_presence(username):
    broadcaster = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcaster.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    message = {"username": username}

    while True:
        data = json.dumps(message).encode()
        broadcaster.sendto(data, (BROADCAST_IP, PORT))     # Normal kısım
        #for ip in BROADCAST_IPS:                            # Hamachi Kısmı 
         #   broadcaster.sendto(data, (ip, PORT))                # Hamacgi kısmı

        time.sleep(BROADCAST_INTERVAL)

if __name__ == "__main__": #So it can run independently
    username = input("Enter your username: ")
    announce_presence(username)
