import warnings
import logging
import scapy.config

# 1. Suppress Python warnings (such as Scapy's SyntaxWarning on layer-3 send())
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 2. Disable Scapy's runtime and interface warning logs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy.config.conf.verb = 0  # Silences scapy's print verbosity globally

from core.menu import offensive_menu, defensive_menu

def main():
    while True:
        print("\n=== PacketWarrior ===")
        print("[1] Offensive Mode")
        print("[2] Defensive Mode")
        print("[0] Exit")

        choice = input("Select: ").strip()

        if choice == "1":
            offensive_menu()
        elif choice == "2":
            defensive_menu()
        elif choice == "0":
            print("Bye!")
            break


if __name__ == "__main__":
    main()