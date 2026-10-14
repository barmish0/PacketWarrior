from core.sniffer import NetworkSniffer
from offensive.arp_spoofer import continuous_arp_dos
from offensive.dhcp_starvation import start_starve
from defensive.arp_guard import check_packet
from core.scanner import display_scan
from defensive.dhcp_guard import check_dhcp_packet


def offensive_menu():
    while True:
        print("\n--- Offensive Mode (Red Team) ---")
        print("[1] Scan Network")
        print("[2] ARP Spoofer (L2)")
        print("[3] DHCP Starvation (L2)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        if choice == "1":
            subnet = input("Enter subnet to scan [default 192.168.1.0/24]: ").strip()
            if not subnet:
                subnet = "192.168.1.0/24"
            display_scan(subnet)

        elif choice == "2":
            victim = input("Victim IP [default 192.168.1.194]: ").strip()
            if not victim:
                victim = "192.168.1.194"
            continuous_arp_dos(victim_ip=victim)

        elif choice == "3":
            dhcp_server = input("Enter DHCP Server IP [default 192.168.1.1]: ").strip()
            if not dhcp_server:
                dhcp_server = "192.168.1.1"

            start_starve(target_ip=dhcp_server)

        elif choice == "0":
            break


def defensive_menu():
    while True:
        print("\n--- Defensive Mode (Blue Team) ---")
        print("[1] Run ARP Guard (L2)")
        print("[2] Run DHCP Guard (L2)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        if choice == "1":
            print("[*] ARP Guard started. Listening...")
            sniffer = NetworkSniffer(packet_filter="arp", action_on_packet=check_packet)
            sniffer.start()
            input("Press Enter to stop ARP Guard...\n")
            sniffer.stop()
            print("[*] ARP Guard stopped.")

        elif choice == "2":
            dhcp_server = input("Enter DHCP Server IP [default 192.168.1.1]: ").strip()
            if not dhcp_server:
                dhcp_server = "192.168.1.1"

            print(f"[*] DHCP Guard active. Monitoring ports 67/68 for attacks on {dhcp_server}...")
            sniffer = NetworkSniffer(
                packet_filter="udp and (port 67 or port 68)",
                action_on_packet=lambda pkt: check_dhcp_packet(pkt, server_ip=dhcp_server)
            )
            sniffer.start()
            input("Press Enter to stop DHCP Guard...\n")
            sniffer.stop()
            print("[*] DHCP Guard stopped.")

        elif choice == "0":
            break