import threading
from scapy.all import sniff

class NetworkSniffer:
    """Multi-threaded wrapper around Scapy's packet sniffing engine."""
    def __init__(self, network_interface = None, packet_filter = None, action_on_packet = None):
        # Network interface to listen on (None selects system default)
        self.network_interface = network_interface

        # BPF (Berkeley Packet Filter) rule string to isolate specific traffic
        self.packet_filter = packet_filter

        # Callback function executed for each intercepted packet matching the filter
        self.action_on_packet = action_on_packet

        # Background worker thread and stop control flag
        self.sniffer_thread = None
        self.should_stop = False

    def listen_loop(self):
        """Core sniffing loop executed inside a separate background thread."""
        sniff(
            iface = self.network_interface,
            filter = self.packet_filter,
            prn = self.action_on_packet,
            stop_filter = self.check_if_should_stop,
            store = False  # Important: store=False prevents memory overflow during long captures
        )

    def check_if_should_stop(self):
        """Condition callback used by Scapy to safely terminate the sniff loop."""
        return self.should_stop

    def start(self):
        """Spawns the background sniffer worker thread."""
        if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
            print("Sniffer is already running.")
            return

        self.should_stop = False
        self.sniffer_thread = threading.Thread(target = self.listen_loop)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        print("Sniffer started successfully.")

    def stop(self):
        """Signals the sniffer thread to stop and waits for clean exit."""
        if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
            self.should_stop = True
            self.sniffer_thread.join(timeout = 2.0)
            print("Sniffer stopped.")