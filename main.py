import time
from core.sniffer import NetworkSniffer

def handle_captured_packet(packet):
    print(f"Captured: {packet.summary()}")

print("Initializing sniffer...")

# Listen for ARP or ICMP
test_sniffer = NetworkSniffer(
    packet_filter="arp or icmp",
    action_on_packet=handle_captured_packet
)

# Start background sniffing
seconds = int(input("Enter the amount of time to run the sniffer (in seconds, integer only): "))
test_sniffer.start()


print(f"Sniffer is running for {seconds} seconds. Generate traffic.")
time.sleep(seconds)

# Stop the sniffer
test_sniffer.stop()
print("Test completed.")