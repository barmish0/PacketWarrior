from core.sniffer import NetworkSniffer
from offensive.arp_spoofer import continuous_arp_dos
from defensive.arp_guard import check_packet
from core.scanner import display_scan


def offensive_menu():
    while True:
        print("\n--- Offensive Mode (Red Team) ---")
        print("[1] Scan Network (Find Targets)")
        print("[2] ARP Spoofer")
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

        elif choice == "0":
            break


def defensive_menu():
    while True:
        print("\n--- Defensive Mode (Blue Team) ---")
        print("[1] Run ARP Guard")
        print("[0] Back to Main Menu")

        choice = input("Select: ").strip()

        if choice == "1":
            print("[*] ARP Guard started. Listening...")
            sniffer = NetworkSniffer(packet_filter="arp", action_on_packet=check_packet)
            sniffer.start()
            input("Press Enter to stop ARP Guard...\n")
            sniffer.stop()
            print("[*] ARP Guard stopped.")
        elif choice == "0":
            break