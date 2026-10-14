import socket
import ipaddress
from scapy.all import conf, get_if_hwaddr


def get_my_ip() -> str:
    """Finds the local IP address used for outbound internet traffic."""
    # Create a dummy UDP socket to evaluate active routing path
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting to an external address forces the OS to pick the correct active interface IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_default_gateway() -> str:
    """
    Extracts the true router IP (default gateway) from the routing table,
    ensuring it does not accidentally return the host's own local IP.
    """
    my_ip = get_my_ip()

    try:
        # Search all routes in Scapy's internal routing table
        default_routes = []
        for dest, mask, gw, iface, out_ip, metric in conf.route.routes:
            # Default gateway routes target destination 0.0.0.0 with netmask 0.0.0.0
            if dest == 0 and mask == 0:
                # Exclude invalid gateway entries like 0.0.0.0 or the host's own IP
                if gw not in ("0.0.0.0", my_ip):
                    default_routes.append((metric, gw))

        if default_routes:
            # Sort by metric to pick the highest priority route (lowest metric value)
            default_routes.sort(key=lambda x: x[0])
            return default_routes[0][1]

    except Exception:
        pass

    # Safe mathematical fallback if routing table lookup fails
    octets = my_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.1"


def get_my_mac(iface=None) -> str:
    """Resolves the MAC address of the active network interface."""
    try:
        target_iface = iface or conf.iface
        return get_if_hwaddr(target_iface)
    except Exception:
        return "00:00:00:00:00:00"


def get_my_subnet() -> str:
    """Calculates the local CIDR subnet mask."""
    my_ip = get_my_ip()
    # Match local IP against active routing entries to determine network mask
    for net, mask, gw, iface, addr, metric in conf.route.routes:
        if addr == my_ip and net != 0 and mask != 0:
            try:
                cidr = ipaddress.IPv4Network((net, mask), strict=False)
                return str(cidr)
            except Exception:
                pass

    # Standard /24 fallback based on local IP structure
    octets = my_ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"