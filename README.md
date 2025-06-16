# Offensive_Computer_Security

There are 2 sections in this README:
1. The GUI
2. The ARP spoofing guige 
3. The DNS spoofing guide
4. The SSL stripping guide
5. The MITM guide

# Graphical User Interface (GUI)

## Software Overview

Desktop UI for launching DNS spoofing, ARP poisoning and SSL stripping with using Scapy. And PySlide6 is used to create the UI. It includes real time logging of what has happened and there is a built in help pdf that the users can use whne they are lost.

## Prerequisites (these can change in the future this is what we thought at the moment)

Operating System: Linux
Python: 3.7 or newer
Permissions: Run with root/administrator rights

## Installation

Install required packages:
```bash
pip install scapy PySide6 PyYAML
```
Place the main script (ui.py) and help.pdf in the same folder.

## Launching the Application
Run the UI with sudo (or equivalent):
```bash
sudo python -m hackingapp.app
```

## Main Window Layout

### Toolbar (Top)
• Interface: Dropdown to select your network adapter (e.g. eth0, wlan0) (this is not fully integrated at the moment)
• Load DNS Mapping…: Opens file dialog to load a YAML file mapping domains to spoofed IPs
• Help: Opens the bundled help.pdf in your system’s default PDF viewer (help.pdf is not yet ready as we are currently working on it; so, there is only a test pdf)
• Quit: Closes the application

### Targets Panel (Left)
A table with columns IP, Mask, Spoof IP
Click + Add row to insert a new target for ARP poisoning

### Modes Panel (Center) (these modes are not implemented; hwoever we have some progress on ARP poisoning and DNS spoofing)
Checkboxes to enable one or more attack modes:
• ARP Poisoning
• DNS Spoofing
• SSL Stripping

### Logs Panel (Right)
Live, timestamped output showing ARP replies sent and DNS queries spoofed

### Control Buttons (Bottom)
• Silent / All-Out (radio buttons): choose between stealth or aggressive timing (not yet implemented)
• Start: Begin selected attacks
• Pause / Resume: Temporarily suspend and resume packet loops (not yet implemented)
• Stop: Halt all activity and threads


### Pausing and Resuming

Click Pause to suspend packet loops without killing threads

Button label switches to Resume—click again to continue


### Stopping

Click Stop to terminate all attacks and return to an idle state


### Help

Click the Help button to open help.pdf

If the PDF is missing, you’ll see an error prompt
# VMs setup

| VM role | Example IP | Example MAC | Notes |
|---------|------------|-------------|-------|
| **Attacker** | `10.0.50.5` | `08:00:27:AA:BB:01` | runs `ARPPoisoner`, enable IP-forward |
| **Victim 1** | `10.0.50.11` | `08:00:27:AA:BB:11` | |
| **Victim 2** *(optional)* | `10.0.50.12` | `08:00:27:AA:BB:12` | second target |
| **Gateway / Router** | `10.0.50.1` | `52:54:00:12:35:00` | VM-net virtual router |

* All NICs sit on the **same Host-Only / Internal** switch (no NAT / Bridged).  
* Discover each address & MAC:

```bash
ip addr show                # own IP & MAC
ip route | grep default     # gateway IP
ip neigh | grep <gw-ip>     # gateway MAC
```
# ARP Poisoning 

A **Scapy‑powered toolkit** that ships in two flavours:

1. **Fully‑fledged CLI** – run complex attacks from the terminal (`arp.py`).

---


##  Features

| Mode               | Purpose                                                                              |
| ------------------ | ------------------------------------------------------------------------------------ |
| **Pair** (default) | Poison one or more `<victim IP, gateway IP>` pairs – classic MITM.                   |
| **Flood**          | Claim **every IP** in a CIDR is at the attacker’s MAC; causes widespread disruption. |
| **Silent**         | Only answers when ARP *requests* are observed – stealthier than active spraying.     |

Additional goodness:

* **Active/Silent toggle** – choose periodic bursts (`--interval`) or reactive replies.
* **Automatic MAC resolution** – queries real MACs before forging packets.
* **Graceful shutdown** – real ARP entries are restored on *Ctrl‑C* (pair + silent modes).
* **Threaded design** – mix multiple pair lists, flood, and silent responders concurrently.
* **Pluggable logging** – Python `logging` with console output by default.

---

##  Requirements

| Item       | Version / Notes                            |
| ---------- | ------------------------------------------ |
| Python     | 3.8 +                                      |
| Scapy      | `pip install scapy`                        |
| OS         | Linux / \*BSD / macOS (raw‑socket support) |
| Privileges | Run as **root** or with `CAP_NET_RAW`      |

---

## Installation

```bash
# 1. Clone repo (or copy the files)
$ git clone https://github.com/your-handle/arp-poisoner.git
$ cd arp-poisoner

# 2. (Optional) Virtual env
$ python3 -m venv venv && source venv/bin/activate

# 3. Install deps
$ pip install -r requirements.txt  # currently just scapy
```

---

##  CLI Quick Start

```bash
# Active pair poisoning (default)
sudo python3 arp_poisoner_fully_fledged.py \
    --iface enp0s10 \
    --victims 10.0.123.4,10.0.123.7 \
    --gateway 10.0.123.1 \
    --interval 4

# Flood an entire /24 every 10 s
sudo python3 arp_poisoner_fully_fledged.py \
    --iface enp0s10 \
    --mode flood \
    --cidr 10.0.123.0/24 \
    --gateway 10.0.123.1

# Silent responder (reactive only)
sudo python3 arp_poisoner_fully_fledged.py \
    --iface enp0s10 \
    --mode silent \
    --victims 10.0.123.4 \
    --gateway 10.0.123.1
```

### CLI Reference

| Option         | Default    | Description                                          |
| -------------- | ---------- | ---------------------------------------------------- |
| `--iface, -i`  | *required* | Network interface to send/receive on (e.g., `eth0`). |
| `--mode`       | `pair`     | `pair`, `flood`, or `silent`.                        |
| `--victims`    | –          | Comma‑separated victim IPs (`pair`/`silent`).        |
| `--gateway`    | –          | Gateway IP (`pair`/`silent`/`flood`).                |
| `--cidr`       | –          | CIDR block to flood (`flood` mode).                  |
| `--interval`   | `10`       | Seconds between bursts in active modes.              |
| `--no‑restore` | *False*    | Skip pushing real MACs back on exit (pair modes).    |

Run `-h/--help` to see the full list any time.

---

##  Library Usage

```python
from arppoisoner import ARPPoisoner
import time

poisoner = ARPPoisoner(log=lambda m: print(f"[+] {m}"))
poisoner.setInterface("eth0")
poisoner.setTargets([
    ("192.168.1.10", "192.168.1.1"),
    ("192.168.1.1",  "192.168.1.10"),
])
poisoner.start()
try:
    time.sleep(60)
finally:
    poisoner.stop()
```

---

##  How It Works (Very Short)

* **ARP cache** ⇒ local table of IP→MAC mappings used by hosts to send Ethernet frames.
* Tool forges **ARP *reply* packets** claiming: `spoof_ip is‑at attacker_mac`.
* Victims update their cache, redirecting IPv4 traffic to you. Combine with packet‑forwarding + `iptables`/`pf` for full man‑in‑the‑middle.

---

##  Cleanup / Restoration

Pair & silent modes automatically push correct MACs back **5×** on exit. If you skipped restoration (`--no-restore`) or used flood mode, caches will age out naturally (typically 1–5 min). You can also broadcast real entries manually:

```bash
# restore: <gateway_ip> is‑at <gateway_mac>
```

---

##  Roadmap

* IPv6 (Neighbor Discovery) support
* DNS‑spoof helper integrated into silent mode
* PyPI & standalone `.deb` package
* pytest‑based test‑suite using Scapy’s offline PCAPs


# DNS Spoofer Tool

> **High‑performance, IPv4/IPv6 DNS spoofer & relay with wildcard YAML mappings**

###  Features

* **IPv6 ready** – answers both A (IPv4) and AAAA (IPv6) queries and forges IPv6 packets where needed.
* **DNS‑over‑TCP support** – crafts sequence‑correct TCP responses so Windows, DoH fallback, and other picky resolvers accept spoofed answers.
* **Multiple answers per name** – map a hostname to **one IP or an IP list** (`A` or `AAAA` records) in a human‑friendly YAML file.
* **Wildcard patterns** – `*.example.com` entries supported (works with lists too).
* **Configurable TTL** – choose how long poisoned answers stick with `--ttl`.
* **Relay mode** – optionally forward unmatched queries to an upstream resolver (`--relay`).
* **Custom BPF filter** – `--bpf` lets you limit sniffing to a victim subnet.
* **Silent ⇄ Verbose logging** – `--quiet` and `--verbose` flip logging level.
* **Graceful shutdown** – UDP and TCP sniffers exit cleanly on *Ctrl‑C*.

###  Requirements

| Item       | Version / Notes            |
| ---------- | -------------------------- |
| Python     | 3.8 +                      |
| Scapy      | `pip install scapy PyYAML` |
| OS         | Linux / \*BSD / macOS      |
| Privileges | root / `CAP_NET_RAW`       |

###  Installation

```bash
$ git clone https://github.com/your-handle/dns-spoofer.git
$ cd dns-spoofer
$ python3 -m venv venv && source venv/bin/activate  # optional
$ pip install -r requirements.txt  # scapy==*, PyYAML==*
```

### 🗂 YAML Mapping Format

```yaml
# map single host to one IP
example.com: 93.184.216.34

# map host to multiple IPv4 addrs (round‑robin style)
foo.example.com:
  - 10.10.10.10
  - 10.10.10.11

# wildcard mapping with IPv6 answers
aaaa:dead::beef:
"*.corp.lan":
  - 2001:db8:dead:beef::1
  - 2001:db8:dead:beef::2
```

> **Tip:** entries are validated at launch; invalid IPs are logged & skipped.

###  CLI Quick Start

```bash
# Basic spoofing (UDP+TCP)
sudo python3 dns_spoofer.py \
    --iface enp0s10 \
    --map hosts.yml

# Add wildcard & IPv6, relay anything else to 1.1.1.1, quieter logs
sudo python3 dns_spoofer.py \
    --iface enp0s10 \
    --map hosts.yml \
    --relay --upstream 1.1.1.1 \
    --ttl 120 \
    --quiet

# Focus only on a victim subnet using a BPF AND clause
sudo python3 dns_spoofer.py \
    --iface enp0s10 \
    --map hosts.yml \
    --bpf "src net 10.0.123.0/24"
```

### CLI Reference (key flags)

| Option         | Default    | Description                               |
| -------------- | ---------- | ----------------------------------------- |
| `-i, --iface`  | *required* | Interface to bind/sniff on.               |
| `-m, --map`    | *required* | YAML mapping file with hostname⇨IP(s).    |
| `--relay`      | *False*    | Relay unmatched queries to `--upstream`.  |
| `--upstream`   | `8.8.8.8`  | Upstream resolver for relay mode.         |
| `--ttl`        | `300`      | TTL seconds for forged answers.           |
| `--bpf`        | –          | Extra BPF filter (AND‑ed with `port 53`). |
| `-q/--quiet`   | *False*    | Errors only.                              |
| `-v/--verbose` | *False*    | Full debug output.                        |

Run `-h/--help` any time for the exhaustive list.

###  How It Works (Mini‑overview)

1. **Sniffs** DNS queries (UDP & TCP) on the specified interface using BPF.
2. **Looks up** the queried QNAME in the YAML mapping (wildcards allowed).
3. **Forges** a compliant DNS answer packet (IPv4 or IPv6) with chosen TTL.
4. **Sends** it back — for TCP, sequence/ack numbers are adjusted correctly.
5. Optionally **relays** unmatched queries via a minimal UDP upstream proxy.

###  Stopping & Cleanup

Hit *Ctrl‑C*. Both UDP and TCP sniffers break out and the main thread joins. No further action is needed—DNS caches eventually age‑out after the TTL.

### 🗺️ Roadmap

* EDNS0 & DNSSEC awareness (forwarded intact in relay mode)
* mDNS / LLMNR spoof helpers
* Docker image & PyPI package
* Unit tests with prerecorded PCAPs



