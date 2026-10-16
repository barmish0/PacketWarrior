import time
import subprocess
import platform
from collections import deque
from scapy.all import sendp, conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

# Attack tracking parameters
RATE_LIMIT_WINDOW = 3.0     # Lookback period in seconds
MAX_REQUESTS_IN_WINDOW = 6  # Alert threshold for rapid DHCP requests
COOLDOWN_PERIOD = 2.0       # Minimum seconds between repeated alert banners

request_history = deque()
blocked_sources = set()
last_alert_time = 0.0


def get_active_iface():
    """Returns the exact network interface used for outbound traffic."""
    try:
        return conf.route.route("8.8.8.8")[0]
    except Exception:
        return conf.iface


def extract_client_mac(packet) -> str:
    """
    Extracts the client MAC address from the BOOTP chaddr field first
    (since starvation tools randomize BOOTP chaddr), falling back to Ether.src.
    """
    try:
        if packet.haslayer(BOOTP):
            raw_chaddr = bytes(packet[BOOTP].chaddr)[:6]
            if raw_chaddr and raw_chaddr != b"\x00" * 6:
                return ":".join(f"{b:02x}" for b in raw_chaddr)
    except Exception:
        pass

    if packet.haslayer(Ether):
        return packet[Ether].src.lower()
    return "00:00:00:00:00:00"


def send_dhcp_release(claimed_ip: str, client_mac: str, server_ip: str, iface=None):
    """
    Counter-action: Forcibly releases a starved IP lease back to the DHCP pool.
    """
    try:
        # BOOTP chaddr field must be exactly 16 bytes (6-byte MAC + 10 null bytes)
        clean_mac = client_mac.replace(":", "").replace("-", "")
        raw_mac = bytes.fromhex(clean_mac).ljust(16, b"\x00")

        rel = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        rel /= IP(src=claimed_ip, dst=server_ip)
        rel /= UDP(sport=68, dport=67)
        rel /= BOOTP(chaddr=raw_mac, ciaddr=claimed_ip)
        rel /= DHCP(options=[
            ("message-type", "release"),
            ("server_id", server_ip),
            ("end")
        ])

        target_iface = iface or get_active_iface()
        sendp(rel, iface=target_iface, verbose=False)
        print(f"[RECOVER] Sent DHCPRELEASE for {claimed_ip} (MAC: {client_mac}) -> Freed lease back to pool.")
    except Exception as e:
        print(f"[-] Failed to send DHCPRELEASE: {e}")


def block_ip_firewall(source_ip: str):
    """
    Dynamically blocks a host at the OS-level firewall across Windows, macOS, and Linux.
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

        elif os_type == "Darwin":  # macOS
            # Add offending IP to a macOS pfctl table
            cmd = (
                f'pfctl -t packetwarrior_blocks -T add {source_ip} 2>/dev/null || '
                f'(echo "table <packetwarrior_blocks> persist\\nblock in quick from <packetwarrior_blocks>" '
                f'| pfctl -a packetwarrior -f - 2>/dev/null && pfctl -t packetwarrior_blocks -T add {source_ip} 2>/dev/null)'
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] macOS pfctl rule injected: Blocked {source_ip}")

        elif os_type == "Linux":
            cmd = f"iptables -A INPUT -s {source_ip} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            blocked_sources.add(source_ip)
            print(f"[FIREWALL] Linux iptables rule injected: Dropped {source_ip}")
    except Exception as err:
        print(f"[-] Could not inject firewall rule: {err}")


def check_dhcp_packet(packet, server_ip="192.168.1.1"):
    """
    Analyzes DHCP transactions, detects high-frequency anomalies,
    and counters rogue pool exhaustion.
    """
    global last_alert_time

    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return

    # Parse DHCP options safely
    options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
    msg_type = options.get("message-type")

    current_time = time.time()
    client_mac = extract_client_mac(packet)

    # 1 = Discover, 3 = Request (Client-to-Server packets)
    if msg_type in (1, 3, "discover", "request"):
        # 1. Update sliding window
        request_history.append((current_time, client_mac))
        while request_history and request_history[0][0] < current_time - RATE_LIMIT_WINDOW:
            request_history.popleft()

        # 2. Check for threshold breach
        if len(request_history) >= MAX_REQUESTS_IN_WINDOW:
            unique_macs = {mac for _, mac in request_history}

            # Apply cooldown so the terminal does not get flooded on every single packet
            if current_time - last_alert_time > COOLDOWN_PERIOD:
                print("\n" + "!" * 65)
                print(f"[BLUE ALERT] DHCP Starvation detected! {len(request_history)} requests in {RATE_LIMIT_WINDOW}s")
                print(f"[!] Involved MAC patterns: {len(unique_macs)} unique addresses")
                print("!" * 65)
                last_alert_time = current_time

            # 3. Active remediation: Release claimed leases if requested_addr or ciaddr is present
            requested_ip = options.get("requested_addr") or packet[BOOTP].ciaddr
            if requested_ip and requested_ip != "0.0.0.0":
                send_dhcp_release(
                    claimed_ip=requested_ip,
                    client_mac=client_mac,
                    server_ip=server_ip
                )

            # 4. Host firewall mitigation (if Layer 3 source is established)
            if packet.haslayer(IP) and packet[IP].src not in ("0.0.0.0", "255.255.255.255", server_ip):
                block_ip_firewall(packet[IP].src)

    # 2 = Offer, 5 = ACK (Server-to-Client replies during an active attack)
    # If an attack is currently happening and the router assigns an IP (yiaddr), release it immediately!
    elif msg_type in (2, 5, "offer", "ack"):
        # Prune old entries first
        while request_history and request_history[0][0] < current_time - RATE_LIMIT_WINDOW:
            request_history.popleft()

        if len(request_history) >= MAX_REQUESTS_IN_WINDOW:
            assigned_ip = packet[BOOTP].yiaddr
            if assigned_ip and assigned_ip != "0.0.0.0":
                send_dhcp_release(
                    claimed_ip=assigned_ip,
                    client_mac=client_mac,
                    server_ip=server_ip
                )