import time
import subprocess
import platform
from collections import deque
from scapy.all import sendp
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# Attack tracking parameters
RATE_LIMIT_WINDOW = 3.0  # Lookback period in seconds
MAX_REQUESTS_IN_WINDOW = 6  # Alert threshold for rapid DHCP requests

request_history = deque()
blocked_sources = set()


def send_dhcp_release(claimed_ip: str, client_mac: str, server_ip: str, iface=None):
    """
    Counter-action: Forcibly releases a starved IP lease back to the DHCP pool.
    """
    try:
        # MAC formatting
        raw_mac = bytes.fromhex(client_mac.replace(":", ""))

        rel = Ether(dst="ff:ff:ff:ff:ff:ff")
        rel /= IP(src=claimed_ip, dst=server_ip)
        rel /= UDP(sport=68, dport=67)
        rel /= BOOTP(chaddr=raw_mac, ciaddr=claimed_ip)
        rel /= DHCP(options=[
            ("message-type", "release"),
            ("server_id", server_ip),
            ("end")
        ])

        sendp(rel, iface=iface, verbose=False)
        print(f"[RECOVER] Sent DHCPRELEASE for {claimed_ip} (Freed lease back to pool).")
    except Exception as e:
        print(f"[-] Failed to send DHCPRELEASE: {e}")


def block_ip_firewall(source_ip: str):
    """
    Dynamically blocks a host at the OS-level firewall.
    """
    if source_ip in blocked_sources or source_ip in ("0.0.0.0", "255.255.255.255"):
        return

    os_type = platform.system()
    try:
        if os_type == "Windows":
            cmd = (
                f'netsh advfirewall firewall add rule name="DHCP_Block_{source_ip}" '
                f'dir=in action=block remoteip={source_ip}'
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] Windows Firewall rule injected: Blocked {source_ip}")
        elif os_type == "Linux":
            cmd = f"iptables -A INPUT -s {source_ip} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] iptables rule injected: Dropped {source_ip}")
    except Exception as err:
        print(f"[-] Could not inject firewall rule: {err}")


def check_dhcp_packet(packet, server_ip="192.168.1.1"):
    """
    Analyzes DHCP transactions, detects high-frequency anomalies,
    and counters rogue pool exhaustion.
    """
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return

    options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
    msg_type_code = options.get("message-type")

    # 1 = Discover, 3 = Request
    if msg_type_code not in (1, 3):
        return

    current_time = time.time()
    src_mac = packet[Ether].src
    requested_ip = options.get("requested_addr", packet[BOOTP].ciaddr)

    # 1. Update sliding window
    request_history.append((current_time, src_mac))
    while request_history and request_history[0][0] < current_time - RATE_LIMIT_WINDOW:
        request_history.popleft()

    # 2. Check for threshold breach
    if len(request_history) >= MAX_REQUESTS_IN_WINDOW:
        unique_macs = {mac for _, mac in request_history}

        print("\n" + "!" * 65)
        print(f"[BLUE ALERT] DHCP Starvation detected! {len(request_history)} requests in {RATE_LIMIT_WINDOW}s")
        print(f"[!] Involved MAC patterns: {len(unique_macs)} unique addresses")
        print("!" * 65)

        # 3. Active remediation: Release claimed leases
        if requested_ip and requested_ip != "0.0.0.0":
            send_dhcp_release(
                claimed_ip=requested_ip,
                client_mac=src_mac,
                server_ip=server_ip
            )

        # 4. Host firewall mitigation (if layer 3 source is established)
        if packet.haslayer(IP) and packet[IP].src != "0.0.0.0":
            block_ip_firewall(packet[IP].src)