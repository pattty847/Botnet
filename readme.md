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

1. Clone the repository:
   ```bash
   git clone https://github.com/pattty847/ChaosBotNet.git
   cd ChaosBotNet
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run components in a lab environment (e.g., VirtualBox):

   - Start C2:
     ```bash
     python c2.py
     ```
   - Deploy dropper:
     ```bash
     python drop.py
     ```
   - Launch bot:
     ```bash
     python bot.py
     ```

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

### Documentation for Very Important Functions

#### From `bot.py`

1. **`real_encrypt(data)`**
   - **What It Does**: Locks data (like secret messages) with a strong lock (AES-256 encryption) so only the bot and C2 server can read it.
   - **How It Works**: Takes any text or data, adds padding (like stuffing a box to fit), and scrambles it using a 32-byte key and a 16-byte starting point (IV). The result is encoded into a safe format (base64).
   - **Why It Matters**: Keeps bot commands and replies secret from snoopers, like using a secret code in a spy game.
   - **Example**: If `data = "attack now"`, it turns into something like `U2FsdGVkX1+...`, unreadable without the key.
   - **Contribution**: Protects communication, making the bot harder to detect or block.

2. **`set_persistence()`**
   - **What It Does**: Makes sure the bot restarts every time the computer turns on.
   - **How It Works**: Adds the bot to three places:
     1. Windows startup list (registry).
     2. A timed job (scheduled task).
     3. A hidden trigger (WMI) that runs it when new programs start.
   - **Why It Matters**: Ensures the bot stays active even if the system restarts, like a weed that keeps growing back.
   - **Example**: After running, you’d see a random name like `KjPxQwRt` in the registry pointing to the bot’s file.
   - **Contribution**: Keeps the botnet alive long-term, infecting more devices.

3. **`hybrid_tunnel()`**
   - **What It Does**: Talks to the C2 server secretly using two methods: DNS (like hidden notes in domain name requests) and HTTPS (disguised web traffic).
   - **How It Works**: Loops forever, fetching tasks via DNS or HTTPS, running them, and sending results back. It waits randomly (5-15 seconds) to look normal.
   - **Why It Matters**: Lets the bot get orders without being caught by firewalls, like whispering in a crowded room.
   - **Example**: It might ask `chaos.evildns.com` for a task like “flood this site” and reply with “done.”
   - **Contribution**: Links bots to the C2 server reliably, forming the botnet’s backbone.

4. **`inject_hollow(target_path=None)`**
   - **What It Does**: Sneaks the bot’s code into a normal program (e.g., Notepad) to hide it.
   - **How It Works**: Starts a program in “sleep mode,” swaps its code with the bot’s, then wakes it up to run secretly.
   - **Why It Matters**: Hides the bot from antivirus by pretending to be something harmless, like a wolf in sheep’s clothing.
   - **Example**: Opens `notepad.exe`, replaces its memory with bot code, and runs it invisibly.
   - **Contribution**: Boosts stealth, making the bot harder to spot.

#### From `c2.py`

5. **`network_chaos_worker()`**
   - **What It Does**: Attacks a target with a flood of fake traffic to overwhelm it.
   - **How It Works**: Sends 2000 bursts of TCP, UDP, or HTTP requests per thread, using random IPs and ports. It also tells bots to join in.
   - **Why It Matters**: Simulates a DDoS attack, showing how botnets can disrupt websites or networks.
   - **Example**: Might flood `example.com:80` with “CHAOSCHAOS…” messages, clogging its pipes.
   - **Contribution**: Turns the botnet into a weapon, demonstrating its power.

6. **`ChaosC2Server.handle_client(client, addr)`**
   - **What It Does**: Listens to bots checking in or reporting tasks, then gives them new jobs.
   - **How It Works**: Reads messages from bots (e.g., “I’m here” or “task done”), logs them, and sends encrypted tasks back via Tor.
   - **Why It Matters**: Acts as the botnet’s brain, coordinating all bots like a puppet master.
   - **Example**: A bot says “Bot-123 checked in”; the server replies with “Flood target” in secret code.
   - **Contribution**: Controls the botnet, keeping it organized and active.

#### From `drop.py`

7. **`inject_into_process()`**
   - **What It Does**: Plants the bot into a running program (explorer.exe) to start it quietly.
   - **How It Works**: Finds `explorer.exe`’s ID, writes a fake “helper” file into its memory, and loads it to kick off the bot.
   - **Why It Matters**: Delivers the bot without leaving obvious traces, like sneaking a package into someone’s bag.
   - **Example**: Writes `helper.dll` into `explorer.exe`, which then runs `WindowsUpdate.exe`.
   - **Contribution**: Starts the infection chain, turning a clean system into a bot.
