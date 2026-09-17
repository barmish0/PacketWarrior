import threading
from scapy.all import sniff

class NetworkSniffer:
    def __init__(self, network_interface = None, packet_filter = None, action_on_packet = None):
        # Network interface ('card') to listen on (None selects the system default)
        self.network_interface = network_interface

        # Filter - protocol, specific ip/mac, port number, etc..., (uses BPF grammar)
        self.packet_filter = packet_filter

        # The function that handles each packet received after filterd
        self.action_on_packet = action_on_packet

        # Worker thread and stop flag
        self.sniffer_thread = None
        self.should_stop = False

    def listen_loop(self):
        sniff(
            iface = self.network_interface,
            filter = self.packet_filter,
            prn = self.action_on_packet,
            stop_filter = self.check_if_should_stop,
            store = False # important - to prevent RAM overflow
        )

    def check_if_should_stop(self):
        return self.should_stop

    def start(self):
        if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
            print("Sniffer is already running.")
            return

        self.should_stop = False
        self.sniffer_thread = threading.Thread(target = self.listen_loop)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        print("Sniffer started successfully.")

    def stop(self):
        if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
            self.should_stop = True
            self.sniffer_thread.join(timeout = 2.0)
            print("Sniffer stopped.")