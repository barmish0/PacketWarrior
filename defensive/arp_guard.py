from scapy.all import send
from scapy.layers.l2 import ARP

# A simple dictionary to remember: {"IP": "MAC"}
known_devices = {}


def heal_network(ip_address, real_mac):
    """Tell the network the real MAC address for this IP."""
    print(f"[FIX] Sending real MAC {real_mac} for IP {ip_address}")

    # Send a broadcast message to fix everyone's memory
    fix_packet = ARP(
        op=2,  # 2 means reply
        pdst="255.255.255.255",
        hwdst="ff:ff:ff:ff:ff:ff",
        psrc=ip_address,
        hwsrc=real_mac
    )
    send(fix_packet, count=2, verbose=False)


def check_packet(packet):
    """Check every ARP packet for fake MACs."""
    if not packet.haslayer(ARP):
        return

    sender_ip = packet[ARP].psrc
    sender_mac = packet[ARP].hwsrc.lower()

    # Skip empty or broadcast addresses
    if sender_ip == "0.0.0.0" or sender_mac == "ff:ff:ff:ff:ff:ff":
        return

    # If this is the first time seeing this IP, save it
    if sender_ip not in known_devices:
        known_devices[sender_ip] = sender_mac
        print(f"[+] Saved: {sender_ip} -> {sender_mac}")
        return

    # Check if the MAC changed unexpectedly
    real_mac = known_devices[sender_ip]
    if real_mac != sender_mac:
        print("\n" + "=" * 40)
        print("! WARNING: ARP ATTACK DETECTED !")
        print(f"Target IP: {sender_ip}")
        print(f"Real MAC:  {real_mac}")
        print(f"Fake MAC:  {sender_mac}")
        print("=" * 40)

        # Fix the network
        heal_network(sender_ip, real_mac)