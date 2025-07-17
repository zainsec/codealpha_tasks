# Task 1: Basic Network Sniffer

## Overview
This task involved building a simple network sniffer using Python and Scapy to capture and analyze live network traffic.

## Tools
- Python 3
- Scapy library

## What the Sniffer Does
- Captures IP packets in real time
- Extracts and displays:
  - Source & Destination IPs
  - Protocol type (TCP, UDP, ICMP)
  - Port numbers (for TCP/UDP)
  - Payload (first 50 bytes)
  - Timestamp for each packet

## Sample Output

[14:22:10] [+] New Packet
Source IP : 192.168.1.5
Destination IP : 142.250.185.4
Protocol : TCP
Source Port : 52344
Destination Port : 443
Payload : b'GET / HTTP/1.1\r\nHost: google.com...'

## Key Learnings
- Understood how data flows using IP, TCP, UDP, and ICMP
- Learned how to inspect packets and extract useful info
- Got hands-on with real-time traffic analysis

## 📸 Screenshots
See `/screenshot` for an example of captured packets.
