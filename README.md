# Offensive_Computer_Security

There are 2 sections in this README:

1. The GUI
2. The ARP spoofing guige
3. The DNS spoofing guide
4. The SSL stripping guide
5. The MITM guide

# Graphical User Interface (GUI)

> **NOTE:** all UI code lives on the `ui_dns` branch of this repo or you can use `tries` branch of this repo.
> To fetch it:
> git clone -b ui_dns https://github.com/<your-handle>/Offensive_Computer_Security.git
> cd Offensive_Computer_Security/hackingapp\ui

## Software Overview

This repository is a **Tkinter-based** desktop UI with three core network-attack tools (written in Python 2.7 + Scapy):

- **ARP Spoofing** (`arp_ui.py`): choose interface, mode (`pair`/`silent`/`flood`), targets or CIDR, and interval; spawns `arp.py` in a subprocess and streams its output into a scrollable log.
- **DNS Spoofing** (`dns_ui.py`): select interface, load a YAML mapping file, set relay/upstream options, TTL and BPF filter; launches `dns.py` and shows live `logging` output in a Tk Text widget.
- **SSL Stripping** (`ssl_ui.py`): pick interface, optional BPF and host-wildcards, toggle verbose/quiet; runs `ssl.py` in a background thread and timestamps each line of its stdout in the GUI.

All three can also be launched from a single windows with tabs from (`combined.py`), which uses a `ttk.Notebook` to let you pick the ARP, DNS or SSL panel. Each UI requires root (raw sockets), however when runing (`combined.py`) giving root access also applies to the opened tabs of attacks. This is done by running teh (`combined.py`) by `sudo python2 combined.py`.

## Prerequisites

- **OS:** Linux (must support raw sockets)
- **Python:** 2.7
- **Permissions:** root access

## Install required packages:

```bash
pip2 install scapy scapy PyYAML
```

Also Get Tkinter GUI binding:

```bash
sudo apt-get install python-tk
```

Place the main script (ui.py) and help.pdf in the same folder.

## Launching the Application

Run the combined UI with sudo:

```bash
sudo python2 combined.py
```

To run each UI for each attack:

- ARP Spoofing

```bash
sudo python2 arp_ui.py
```

- DNS Spoofing

```bash
sudo python2 dns_ui.py
```

- SSl Stripping

```bash
sudo python2 ssl_ui.py
```

# VMs Setup

Basic network setup for the **Default Project Victim** and **M3 Attacker**:

> Ensure all VMs are on the same host-only/internal network.

---

# UI Walkthrough

## ARP Spoofing UI (`arp_ui.py`)

- **Interface:**
- **Mode:**
  - `pair` – two-host poisoning
  - `silent` – reactive replies only
  - `flood` – claim every IP in a CIDR
- **Victims (CSV)** + **Gateway** (for `pair`/`silent`)
- **CIDR** + **Gateway** (for `flood`)
- **Interval (s):** seconds between packets
- **Start:** launches `arp.py` with the specified arguments
- **Stop:** sends `SIGINT` and restores ARP caches

## DNS Spoofing UI (`dns_ui.py`)

- **Interface:**
- **Mapping file:** YAML map
- **Relay unmatched:** checkbox to forward other queries
- **Upstream DNS:** default `8.8.8.8`
- **TTL (secs):** lifetime of forged answers
- **BPF filter:** limit the sniffing scope
- **Log level:** `DEBUG` / `INFO` / `ERROR`
- **Start / Stop:** control the `DNSSpoofer` process

## SSL Strip UI (`ssl_ui.py`)

- **Interface:**
- **BPF filter:** optional packet filter
- **Hosts (CSV wildcards):** e.g. `*.example.com`
- **Verbose / Quiet:** toggle logging detail
- **Start:** launches `ssl.py`
- **Stop:** terminates the process
- **Log panel:** each line prefixed `[HH:MM:SS]`

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
| `--iface, -i`  | _required_ | Network interface to send/receive on (e.g., `eth0`). |
| `--mode`       | `pair`     | `pair`, `flood`, or `silent`.                        |
| `--victims`    | –          | Comma‑separated victim IPs (`pair`/`silent`).        |
| `--gateway`    | –          | Gateway IP (`pair`/`silent`/`flood`).                |
| `--cidr`       | –          | CIDR block to flood (`flood` mode).                  |
| `--interval`   | `10`       | Seconds between bursts in active modes.              |
| `--no‑restore` | _False_    | Skip pushing real MACs back on exit (pair modes).    |

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

- **ARP cache** ⇒ local table of IP→MAC mappings used by hosts to send Ethernet frames.
- Tool forges **ARP _reply_ packets** claiming: `spoof_ip is‑at attacker_mac`.
- Victims update their cache, redirecting IPv4 traffic to you. Combine with packet‑forwarding + `iptables`/`pf` for full man‑in‑the‑middle.

---

##  Cleanup / Restoration

Pair & silent modes automatically push correct MACs back **5×** on exit. If you skipped restoration (`--no-restore`) or used flood mode, caches will age out naturally (typically 1–5 min). You can also broadcast real entries manually:

```bash
# restore: <gateway_ip> is‑at <gateway_mac>
```

---

##  Roadmap

- IPv6 (Neighbor Discovery) support
- DNS‑spoof helper integrated into silent mode
- PyPI & standalone `.deb` package
- pytest‑based test‑suite using Scapy’s offline PCAPs

# DNS Spoofer Tool

> **High‑performance, IPv4/IPv6 DNS spoofer & relay with wildcard YAML mappings**

###  Features

- **IPv6 ready** – answers both A (IPv4) and AAAA (IPv6) queries and forges IPv6 packets where needed.
- **DNS‑over‑TCP support** – crafts sequence‑correct TCP responses so Windows, DoH fallback, and other picky resolvers accept spoofed answers.
- **Multiple answers per name** – map a hostname to **one IP or an IP list** (`A` or `AAAA` records) in a human‑friendly YAML file.
- **Wildcard patterns** – `*.example.com` entries supported (works with lists too).
- **Configurable TTL** – choose how long poisoned answers stick with `--ttl`.
- **Relay mode** – optionally forward unmatched queries to an upstream resolver (`--relay`).
- **Custom BPF filter** – `--bpf` lets you limit sniffing to a victim subnet.
- **Silent ⇄ Verbose logging** – `--quiet` and `--verbose` flip logging level.
- **Graceful shutdown** – UDP and TCP sniffers exit cleanly on *Ctrl‑C*.

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
| `-i, --iface`  | _required_ | Interface to bind/sniff on.               |
| `-m, --map`    | _required_ | YAML mapping file with hostname⇨IP(s).    |
| `--relay`      | _False_    | Relay unmatched queries to `--upstream`.  |
| `--upstream`   | `8.8.8.8`  | Upstream resolver for relay mode.         |
| `--ttl`        | `300`      | TTL seconds for forged answers.           |
| `--bpf`        | –          | Extra BPF filter (AND‑ed with `port 53`). |
| `-q/--quiet`   | _False_    | Errors only.                              |
| `-v/--verbose` | _False_    | Full debug output.                        |

Run `-h/--help` any time for the exhaustive list.

###  How It Works (Mini‑overview)

1. **Sniffs** DNS queries (UDP & TCP) on the specified interface using BPF.
2. **Looks up** the queried QNAME in the YAML mapping (wildcards allowed).
3. **Forges** a compliant DNS answer packet (IPv4 or IPv6) with chosen TTL.
4. **Sends** it back — for TCP, sequence/ack numbers are adjusted correctly.
5. Optionally **relays** unmatched queries via a minimal UDP upstream proxy.

###  Stopping & Cleanup

Hit _Ctrl‑C_. Both UDP and TCP sniffers break out and the main thread joins. No further action is needed—DNS caches eventually age‑out after the TTL.

### 🗺️ Roadmap

- EDNS0 & DNSSEC awareness (forwarded intact in relay mode)
- mDNS / LLMNR spoof helpers
- Docker image & PyPI package
- Unit tests with prerecorded PCAPs
