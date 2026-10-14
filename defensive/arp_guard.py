import platform
import subprocess
from scapy.all import sendp, srp1, conf
from scapy.layers.l2 import Ether, ARP
from core.network_info import get_my_ip, get_my_mac, get_default_gateway

# Trusted baseline dictionary: {"IP": "MAC"}
known_devices = {}


def seed_baseline():
    """
    Actively resolves and locks the true gateway and local host MACs
    BEFORE starting the sniffer, so fake attack packets cannot poison the baseline.
    """
    my_ip = get_my_ip()
    my_mac = get_my_mac().lower()
    gateway_ip = get_default_gateway()

    # Save our own interface
    known_devices[my_ip] = my_mac

    # Resolve legitimate router MAC directly
    print(f"[*] Resolving authentic gateway MAC for {gateway_ip}...")
    query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    ans = srp1(query, timeout=2, verbose=False)

    if ans and ans.haslayer(ARP):
        real_gw_mac = ans[ARP].hwsrc.lower()
        known_devices[gateway_ip] = real_gw_mac
        print(f"[+] Trusted Gateway Baseline: {gateway_ip} -> {real_gw_mac}")
    else:
        print(f"[!] Warning: Could not resolve gateway MAC. Guard will learn dynamically.")


def heal_network(ip_address: str, real_mac: str, iface=None):
    """Broadcasts a corrective ARP reply to restore genuine cache mappings."""
    print(f"[FIX] Restoring real mapping: {ip_address} -> {real_mac}")

    # Flush locally on the host OS
    os_name = platform.system()
    try:
        if os_name == "Windows":
            subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True)
        else:
            subprocess.run(f"ip neigh flush {ip_address}", shell=True, capture_output=True)
    except Exception:
        pass

    # Send gratuitous ARP to realign neighbor caches
    target_iface = iface or conf.iface
    fix_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_mac) / ARP(
        op=2,
        hwsrc=real_mac,
        psrc=ip_address,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=ip_address
    )
    sendp(fix_packet, count=3, iface=target_iface, verbose=False)


def check_packet(packet):
    """Inspects every incoming ARP frame."""
    if not packet.haslayer(ARP):
        return

    sender_ip = packet[ARP].psrc
    sender_mac = packet[ARP].hwsrc.lower()

    # Skip loopbacks, broadcasts, or incomplete frames
    if sender_ip in ("0.0.0.0", "255.255.255.255") or sender_mac == "ff:ff:ff:ff:ff:ff":
        return

    # First encounter of this IP: record it
    if sender_ip not in known_devices:
        known_devices[sender_ip] = sender_mac
        print(f"[+] Saved baseline: {sender_ip} -> {sender_mac}")
        return

    # Detection logic: Same IP, different MAC address
    real_mac = known_devices[sender_ip]
    if real_mac != sender_mac:
        print("\n" + "=" * 55)
        print("[BLUE ALERT] ARP SPOOFING / POISONING DETECTED!")
        print(f"Target IP:     {sender_ip}")
        print(f"Authentic MAC: {real_mac}")
        print(f"Attacker MAC:  {sender_mac}")
        print("=" * 55)

        heal_network(sender_ip, real_mac)