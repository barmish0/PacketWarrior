import platform
import subprocess
from scapy.all import sendp, sr1, conf
from scapy.layers.l2 import Ether, ARP
from core.network_info import get_my_ip, get_my_mac, get_default_gateway

# Trusted baseline IP -> MAC mapping
known_devices = {}


def seed_trusted_baseline():
    """
    Seeds trusted MACs for ourselves and the gateway before sniffing begins.
    Prevents the attacker's fake MAC from becoming the baseline.
    """
    my_ip = get_my_ip()
    my_mac = get_my_mac().lower()
    gateway_ip = get_default_gateway()

    known_devices[my_ip] = my_mac
    print(f"[*] Baseline host:    {my_ip} -> {my_mac}")

    # Actively resolve authentic gateway MAC via an active ARP request
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
        ans = sr1(query, timeout=2, verbose=False)
        if ans and ans.haslayer(ARP):
            gw_mac = ans[ARP].hwsrc.lower()
            known_devices[gateway_ip] = gw_mac
            print(f"[*] Baseline gateway: {gateway_ip} -> {gw_mac}")
    except Exception as e:
        print(f"[-] Could not resolve baseline gateway MAC: {e}")


def heal_network(ip_address: str, real_mac: str, iface=None):
    """
    Broadcasts corrective ARP replies and flushes the local OS ARP cache.
    """
    print(f"[FIX] Restoring mapping: {ip_address} -> {real_mac}")

    # 1. Clear or overwrite poisoned entry in local OS table
    os_name = platform.system()
    try:
        if os_name == "Windows":
            subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True)
        else:
            subprocess.run(f"ip neigh flush {ip_address}", shell=True, capture_output=True)
    except Exception:
        pass

    # 2. Transmit corrective Gratuitous ARP broadcast
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
    """Callback passed to NetworkSniffer."""
    if not packet.haslayer(ARP):
        return

    sender_ip = packet[ARP].psrc
    sender_mac = packet[ARP].hwsrc.lower()

    if sender_ip in ("0.0.0.0", "255.255.255.255") or sender_mac == "ff:ff:ff:ff:ff:ff":
        return

    # First time seeing this IP: record it
    if sender_ip not in known_devices:
        known_devices[sender_ip] = sender_mac
        print(f"[+] Saved baseline: {sender_ip} -> {sender_mac}")
        return

    # Detect deviation from recorded baseline
    real_mac = known_devices[sender_ip]
    if real_mac != sender_mac:
        print("\n" + "=" * 55)
        print("[BLUE ALERT] ARP SPOOFING / POISONING DETECTED!")
        print(f"Target IP:     {sender_ip}")
        print(f"Authentic MAC: {real_mac}")
        print(f"Attacker MAC:  {sender_mac}")
        print("=" * 55)

        heal_network(sender_ip, real_mac)