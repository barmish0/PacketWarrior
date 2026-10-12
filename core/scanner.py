import socket
from scapy.all import srp
from scapy.layers.l2 import Ether, ARP


def resolve_hostname(ip: str) -> str:
    """Attempts to find the device's name from its IP."""
    try:
        # Standard reverse DNS lookup
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout):
        return "Unknown"


def scan_network(subnet: str = "192.168.1.0/24", timeout: int = 2):
    """
    Sends an ARP request to the entire subnet to find active devices.
    Returns a list of dictionaries with IP, MAC, and Hostname.
    """
    print(f"[*] Scanning subnet: {subnet} (Timeout: {timeout}s)...")

    # Broadcast Layer 2 request to all devices on the subnet
    broadcast_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    # srp sends at Layer 2 and listens for replies
    answered, _ = srp(broadcast_request, timeout=timeout, verbose=False)

    devices = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        hostname = resolve_hostname(ip)

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname
        })

    return devices


def display_scan(subnet: str = "192.168.1.0/24"):
    """Runs the scan and prints a clean, readable table."""
    results = scan_network(subnet)

    print("\n" + "=" * 65)
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
    print("=" * 65)

    if not results:
        print("No devices found or scan timed out.")
    else:
        for dev in results:
            print(f"{dev['ip']:<18} {dev['mac']:<20} {dev['hostname']}")

    print("=" * 65)
    print(f"[+] Found {len(results)} active device(s).\n")


if __name__ == "__main__":
    display_scan()