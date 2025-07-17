from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if packet has IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'Other')

        print(f"\n[+] New Packet")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {protocol_name}")

        # Display payload if TCP or UDP
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
            print(f"    Payload        : {payload[:50]}...")  # Show only first 50 bytes
    else:
        print("\n[-] Non-IP Packet Captured")

def main():
    print("[*] Starting network sniffer...")
    sniff(prn=packet_callback, store=False)  # Run indefinitely

if __name__ == "__main__":
    main()