from scapy.all import sniff, IP, TCP, UDP, Raw

# ---------------------------
# Configuration
# ---------------------------
FILTER = ""  # e.g., "tcp" or "udp" or "host 192.168.1.10" for filtering
PACKET_COUNT = 0  # 0 = unlimited
PAYLOAD_PREVIEW_BYTES = 20  # number of bytes to show from payload

# ---------------------------
# Function to analyze each packet
# ---------------------------
def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\nSource: {src} -> Destination: {dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}")

        if Raw in packet:
            payload = packet[Raw].load
            # Show only the first few bytes to keep it readable
            print(f"Payload (first {PAYLOAD_PREVIEW_BYTES} bytes): {payload[:PAYLOAD_PREVIEW_BYTES]}")

# ---------------------------
# Start sniffing
# ---------------------------
print("Starting packet sniffer...")
print("Press Ctrl+C to stop.\n")

try:
    sniff(filter=FILTER, prn=analyze_packet, store=False, count=PACKET_COUNT)
except KeyboardInterrupt:
    print("\nSniffer stopped by user. Exiting...")
