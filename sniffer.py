from scapy.all import sniff, IP, TCP, UDP

def packet_info(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "OTHER"
            src_port = "N/A"
            dst_port = "N/A"
            
        print(f"Protocol: {protocol}")
        print(f"Source IP: {src_ip} Port: {src_port}")
        print(f"Destination IP: {dst_ip} Port: {dst_port}")
        print("-" * 40)

print("Starting network sniffer...")
print("Capturing 10 packets...")
sniff(count=10, prn=packet_info)
print("Done!")