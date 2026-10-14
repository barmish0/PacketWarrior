import time
import subprocess
import platform
from collections import deque
from scapy.all import sendp, conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# Attack tracking and rate-limiting parameters
RATE_LIMIT_WINDOW = 3.0  # Sliding time window in seconds
MAX_REQUESTS_IN_WINDOW = 6  # Maximum allowed rapid DHCP transactions before alerting
COOLDOWN_PERIOD = 2.0  # Minimum seconds between repeated console alert banners

request_history = deque()
blocked_sources = set()
last_alert_time = 0.0


def send_dhcp_release(claimed_ip: str, client_mac: str, server_ip: str, iface=None):
    """
    Counter-action: Forcibly releases a starved IP lease back to the DHCP pool.
    """
    try:
        # BOOTP chaddr (client hardware address) must be exactly 16 bytes padded
        raw_mac = bytes.fromhex(client_mac.replace(":", "").replace("-", ""))
        chaddr_padded = raw_mac.ljust(16, b"\x00")

        # Construct crafted DHCP RELEASE packet
        rel = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        rel /= IP(src=claimed_ip, dst=server_ip)
        rel /= UDP(sport=68, dport=67)
        rel /= BOOTP(chaddr=chaddr_padded, ciaddr=claimed_ip)
        rel /= DHCP(options=[
            ("message-type", "release"),
            ("server_id", server_ip),
            ("end")
        ])

        target_iface = iface or conf.iface
        sendp(rel, iface=target_iface, verbose=False)
        print(f"[RECOVER] Sent DHCPRELEASE for {claimed_ip} (Freed lease back to pool).")
    except Exception as e:
        print(f"[-] Failed to send DHCPRELEASE: {e}")


def block_ip_firewall(source_ip: str):
    """
    Dynamically blocks an offending host at the host OS firewall.
    """
    if source_ip in blocked_sources or source_ip in ("0.0.0.0", "255.255.255.255"):
        return

    os_type = platform.system()
    try:
        # Inject firewall rules based on the host operating system
        if os_type == "Windows":
            cmd = (
                f'netsh advfirewall firewall add rule name="PW_Block_{source_ip}" '
                f'dir=in action=block remoteip={source_ip}'
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] Injected Windows Firewall rule: Blocked {source_ip}")
        elif os_type == "Linux":
            cmd = f"iptables -A INPUT -s {source_ip} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] Injected iptables rule: Dropped {source_ip}")
    except Exception as err:
        print(f"[-] Could not inject firewall rule: {err}")


def check_dhcp_packet(packet, server_ip="192.168.1.1"):
    """
    Analyzes DHCP transactions, detects high-frequency bursts,
    and attempts pool recovery.
    """
    global last_alert_time

    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return

    options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
    msg_type = options.get("message-type")

    # Filter only for DHCP Discover (1) or Request (3) messages
    if msg_type not in (1, 3, "discover", "request"):
        return

    current_time = time.time()
    src_mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
    requested_ip = options.get("requested_addr", packet[BOOTP].ciaddr)

    # 1. Update sliding request history window
    request_history.append((current_time, src_mac))
    while request_history and request_history[0][0] < current_time - RATE_LIMIT_WINDOW:
        request_history.popleft()

    # 2. Check if request frequency breaches safety threshold
    if len(request_history) >= MAX_REQUESTS_IN_WINDOW:
        unique_macs = {mac for _, mac in request_history}

        # Apply alert cooldown to prevent console flood
        if current_time - last_alert_time > COOLDOWN_PERIOD:
            print("\n" + "!" * 65)
            print(f"[BLUE ALERT] DHCP Starvation detected! {len(request_history)} requests in {RATE_LIMIT_WINDOW}s")
            print(f"[!] Suspect burst: {len(unique_macs)} unique MAC addresses")
            print("!" * 65)
            last_alert_time = current_time

        # 3. Active remediation: Release claimed leases back to pool
        if requested_ip and requested_ip != "0.0.0.0":
            send_dhcp_release(
                claimed_ip=requested_ip,
                client_mac=src_mac,
                server_ip=server_ip
            )

        # 4. Host firewall mitigation against attacker IP
        if packet.haslayer(IP) and packet[IP].src not in ("0.0.0.0", "255.255.255.255"):
            block_ip_firewall(packet[IP].src)