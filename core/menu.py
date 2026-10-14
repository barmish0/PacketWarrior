from core.sniffer import NetworkSniffer
from core.scanner import display_scan
from core.network_info import get_my_ip, get_my_mac, get_default_gateway, get_my_subnet
from offensive.arp_spoofer import continuous_arp_dos
from offensive.dhcp_starvation import start_starve
from defensive.arp_guard import check_packet, seed_baseline
from defensive.dhcp_guard import check_dhcp_packet


def offensive_menu():
    """Handles the Red Team (Offensive) interactive submenu."""
    # Automatically fetch local networking configuration details
    my_ip = get_my_ip()
    my_mac = get_my_mac()
    gateway = get_default_gateway()
    subnet = get_my_subnet()

    while True:
        # Display current host status and available attack simulation options
        print("\n--- Offensive Mode (Red Team) ---")
        print(f"[*] Host IP: {my_ip} | MAC: {my_mac}")
        print(f"[*] Gateway: {gateway} | Subnet: {subnet}")
        print("=" * 50)
        print("[1] Scan Network")
        print("[2] ARP Spoofer (L2)")
        print("[3] DHCP Starvation (L2)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        # Option 1: Trigger network reconnaissance scan
        if choice == "1":
            user_subnet = input(f"Enter subnet to scan [default {subnet}]: ").strip()
            display_scan(user_subnet if user_subnet else subnet)

        # Option 2: Execute Layer 2 ARP poisoning/DoS attack
        elif choice == "2":
            victim = input("Victim IP: ").strip()
            if not victim:
                print("[-] Victim IP is required.")
                continue

            user_gw = input(f"Gateway IP [default {gateway}]: ").strip()
            user_mac = input(f"Attacker MAC [default {my_mac}]: ").strip()

            continuous_arp_dos(
                victim_ip=victim,
                gateway_ip=user_gw if user_gw else gateway,
                attacker_mac=user_mac if user_mac else my_mac
            )

        # Option 3: Execute Layer 2 DHCP starvation attack
        elif choice == "3":
            dhcp_server = input(f"Enter DHCP Server IP [default {gateway}]: ").strip()
            start_starve(target_ip=dhcp_server if dhcp_server else gateway)

        # Exit submenu loop
        elif choice == "0":
            break


def defensive_menu():
    """Handles the Blue Team (Defensive) interactive submenu."""
    # Automatically fetch local networking configuration details
    my_ip = get_my_ip()
    my_mac = get_my_mac()
    gateway = get_default_gateway()
    subnet = get_my_subnet()

    while True:
        # Display current host status and available defensive monitoring options
        print("\n--- Defensive Mode (Blue Team) ---")
        print(f"[*] Host IP: {my_ip} | MAC: {my_mac}")
        print(f"[*] Gateway: {gateway} | Subnet: {subnet}")
        print("=" * 50)
        print("[1] Run ARP Guard (L2)")
        print("[2] Run DHCP Guard (L2)")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        # Inside defensive_menu():

        # Option 1: Start real-time ARP spoofing detector and auto-healer
        if choice == "1":
            print("[*] Initializing ARP baseline...")
            seed_baseline()
            print("[*] ARP Guard started. Listening...")
            sniffer = NetworkSniffer(packet_filter="arp", action_on_packet=check_packet)
            sniffer.start()
            input("Press Enter to stop ARP Guard...\n")
            sniffer.stop()
            print("[*] ARP Guard stopped.")

        # Option 2: Start DHCP starvation detector, lease releaser, and firewall blocker
        elif choice == "2":
            dhcp_server = input(f"Enter DHCP Server IP [default {gateway}]: ").strip()
            target_gw = dhcp_server if dhcp_server else gateway

            print(f"[*] DHCP Guard active. Monitoring ports 67/68 for attacks against {target_gw}...")
            sniffer = NetworkSniffer(
                packet_filter="udp and (port 67 or port 68)",
                action_on_packet=lambda pkt: check_dhcp_packet(pkt, server_ip=target_gw)
            )
            sniffer.start()
            input("Press Enter to stop DHCP Guard...\n")
            sniffer.stop()
            print("[*] DHCP Guard stopped.")

        # Exit submenu loop
        elif choice == "0":
            break