from scapy.all import sendp
from scapy.layers.l2 import Ether, ARP

# A simple dictionary to remember: {"IP": "MAC"}
known_devices = {}


def heal_network(ip_address: str, real_mac: str, iface=None):
    """
    Broadcasts a corrective Gratuitous ARP reply to restore
    the legitimate IP-to-MAC mapping across local host caches.
    """
    print(f"[FIX] Broadcasting real mapping: {ip_address} -> {real_mac}")

    # Use Layer 2 Ether frame over sendp for reliable physical delivery
    fix_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) / ARP(
        op=2,  # 2 = ARP Reply / Gratuitous ARP
        hwsrc=real_mac,
        psrc=ip_address,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=ip_address
    )
    sendp(fix_packet, count=3, iface=iface, verbose=False)


def check_packet(packet):
    """Inspects ARP traffic for conflicting MAC mappings."""
    if not packet.haslayer(ARP):
        return

    sender_ip = packet[ARP].psrc
    sender_mac = packet[ARP].hwsrc.lower()

    # Ignore empty, loopback, or broadcast sources
    if sender_ip in ("0.0.0.0", "255.255.255.255") or sender_mac == "ff:ff:ff:ff:ff:ff":
        return

    # First time seeing this IP: establish baseline
    if sender_ip not in known_devices:
        known_devices[sender_ip] = sender_mac
        print(f"[+] Saved baseline: {sender_ip} -> {sender_mac}")
        return

    # Check for unauthorized MAC modification
    real_mac = known_devices[sender_ip]
    if real_mac != sender_mac:
        print("\n" + "=" * 55)
        print("[BLUE ALERT] ARP SPOOFING / POISONING DETECTED!")
        print(f"Target IP: {sender_ip}")
        print(f"Authentic MAC: {real_mac}")
        print(f"Attacker MAC: {sender_mac}")
        print("=" * 55)

        # Broadcast correction
        heal_network(sender_ip, real_mac)