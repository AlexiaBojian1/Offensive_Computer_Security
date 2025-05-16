# Offensive_Computer_Security

There are 2 sections in this README:
1. The GUI
2. The DNS spoofing guide

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
sudo python -m hackingapp.app

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


# DNS Spoofer Tool

A simple DNS spoofing and relay tool written in Python using Scapy. It listens for DNS queries on a specified network interface and either forges responses for configured hostnames or relays queries to an upstream DNS server.

---

## Features

* **Targeted Spoofing**: Only spoof domains defined in a YAML mapping file (supports exact names and `*.suffix` wildcards).
* **Relay Mode**: Forward all other queries to a real upstream DNS server and return their answers.
* **Lightweight**: Pure Python with Scapy; no external DNS libraries required.
* **Clean Shutdown**: Handles `Ctrl-C` for a graceful exit.

---

## Requirements

* Python 3.6+
* `scapy`
* `PyYAML`

Install dependencies:

```bash
sudo apt update
sudo apt install python3-pip python3-setuptools libyaml-dev
sudo pip3 install scapy[complete] pyyaml
```

---

## Installation

1. Clone this repository (or copy `dns.py` and `mapping.yml`).
2. Make  the script is executable:

   ```bash
   chmod +x dns.py
   ```

---

## Usage

```bash
sudo python3 ./hackingapp/protocols/dns.py -i <interface> -m <mapping-file> [--relay] [--upstream <server>]
```

* `-i`, `--iface` : Network interface to listen on (e.g., `eth0`).
* `-m`, `--map`   : Path to the YAML mapping file.
* `--relay`      : Relay unmatched queries to the upstream server.
* `--upstream`   : IP address of upstream DNS (default: `8.8.8.8`).

### Example

Given a `mapping.yml`:

```yaml
legit.example.local: 5.6.7.8
*.test.local:      9.9.9.9
```

Run the spoofer on interface `enp0s3` in spoof-only mode:

```bash
sudo python3 ./hackingapp/protocols/dns.py -i enp0s3 -m mapping.yml
```

**On the victim** (configured to use the attacker as DNS):

```bash
$ dig +short legit.example.local
5.6.7.8

$ dig +short foo.test.local
9.9.9.9

$ dig +short other.com
# no reply (unless --relay is used)
```

![Victim & Attacker VMs side-by-side](images/exampleDns.jpeg)

To enable relay mode so that other domains still resolve correctly:

```bash
sudo python3 ./hackingapp/protocols/dns.py -i enp0s3 -m mapping.yml --relay --upstream 10.0.0.1
```

Then:

```bash
$ dig +short other.com
93.184.216.34   # real answer from upstream
```

---

## How It Works

1. **Sniff**: Captures UDP port 53 packets on the chosen interface.
2. **Match**: Checks each query name against the mapping (exact + `*.suffix`).
3. **Spoof**: Crafts a DNS reply (A record, TTL=300s) with the forged IP.
4. **Relay**: If enabled and no match, forwards raw DNS queries to upstream and returns their answers.

Internals:

* Uses Scapy to build and send packets (handles checksums).
* Runs in a daemon thread for easy shutdown.
* Validates mapping file for correct IP syntax.


