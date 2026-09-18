from core.menu import offensive_menu, defensive_menu
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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