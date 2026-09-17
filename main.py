import time
from core.sniffer import NetworkSniffer
from offensive.arp_spoofer import continuous_arp_dos


def main():
    while True:
        print("\n=== PacketWarrior ===")
        print("[1] Sniff ARP")
        print("[2] Run ARP Spoofer")
        print("[0] Exit")

        choice = input("Select: ").strip()

        if choice == "1":
            sniffer = NetworkSniffer("arp", lambda p: print(f"[CAUGHT]: {p.summary()}"))
            sniffer.start()
            input("Press Enter to stop sniffing...")
            sniffer.stop()

        elif choice == "2":
            victim = input("Enter victim IP [default 192.168.1.194]: ").strip()
            if not victim:
                victim = "192.168.1.194"
            continuous_arp_dos(victim_ip=victim)

        elif choice == "0":
            break


if __name__ == "__main__":
    main()