from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol name
        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'Other')

        # Print packet metadata with timestamp
        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] [+] New Packet")
        print(f"    Source IP        : {src_ip}")
        print(f"    Destination IP   : {dst_ip}")
        print(f"    Protocol         : {protocol_name}")

        # Show port numbers and payload
        if packet.haslayer(TCP):
            print(f"    Source Port      : {packet[TCP].sport}")
            print(f"    Destination Port : {packet[TCP].dport}")
            payload = bytes(packet[TCP].payload)
            if payload:
                print(f"    Payload          : {payload[:50]}...")
        elif packet.haslayer(UDP):
            print(f"    Source Port      : {packet[UDP].sport}")
            print(f"    Destination Port : {packet[UDP].dport}")
            payload = bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload          : {payload[:50]}...")
    else:
        print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] [-] Non-IP Packet Captured")

def main():
    print("[*] Starting network sniffer. Press Ctrl+C to stop.\n")
    try:
        # You can use a filter like "ip" or "tcp" if needed
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")

if __name__ == "__main__":
    main()
