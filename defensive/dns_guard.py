import platform
import subprocess
from scapy.layers.inet import IP
from scapy.layers.dns import DNS
from core.logger import log_security_event


def flush_os_dns_cache():
    """Flushes the local operating system DNS cache to clear poisoned records."""
    os_name = platform.system()
    try:
        if os_name == "Windows":
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, text=True)
            print("[FIREWALL] Flushed Windows DNS Cache.")
        elif os_name == "Darwin":  # macOS
            subprocess.run("sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder", shell=True, capture_output=True, text=True)
            print("[FIREWALL] Flushed macOS DNS Cache.")
        elif os_name == "Linux":
            subprocess.run("systemctl restart systemd-resolved 2>/dev/null || service nscd restart 2>/dev/null", shell=True, capture_output=True, text=True)
            print("[FIREWALL] Flushed Linux DNS Cache.")
    except Exception as err:
        print(f"[-] Failed to flush OS DNS cache: {err}")


def check_dns_packet(packet):
    """
    Inspects incoming DNS responses for cache poisoning and rogue spoofing indicators.
    """
    if not packet.haslayer(DNS) or packet[DNS].qr != 1:
        return  # Only inspect DNS responses (qr == 1)

    dns = packet[DNS]
    if not dns.an:
        return

    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Local"

    # Iterate through all Answer records in the DNS response
    for i in range(dns.ancount):
        try:
            ans = dns.an[i]
            if hasattr(ans, "rdata") and hasattr(ans, "rrname"):
                rdata = str(ans.rdata)
                rrname = ans.rrname.decode("utf-8", errors="ignore") if isinstance(ans.rrname, bytes) else str(ans.rrname)
                clean_name = rrname.strip(".")

                # Spoofing Heuristic: If a major external service domain resolves to a private/local IP
                # (e.g. an attacker redirecting login portals to 192.168.x.x or 10.x.x.x)
                major_brands = ["google", "microsoft", "github", "apple", "facebook", "login", "auth", "update"]
                if any(brand in clean_name.lower() for brand in major_brands):
                    if rdata.startswith(("192.168.", "10.", "172.16.", "127.", "0.")):
                        print("\n" + "!" * 65)
                        print(f"[BLUE ALERT] Rogue DNS Spoofing / Cache Poisoning detected!")
                        print(f"[!] Domain '{clean_name}' was resolved to suspicious IP: {rdata}")
                        print("!" * 65)

                        # Log security event to logs/security_alerts.log and logs/events.jsonl
                        log_security_event(
                            module="DNS Guard",
                            event_type="DNS Cache Poisoning / Spoofing",
                            source=src_ip,
                            target=dst_ip,
                            action_taken="OS DNS Cache Flush",
                            details=f"Fake resolution: {clean_name} -> {rdata}"
                        )

                        # Flush poisoned records from the OS DNS cache
                        flush_os_dns_cache()
                        break
        except Exception:
            pass