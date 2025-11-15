from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = packet.proto

        length = len(packet)

        print(f"[+] SRC: {src}  →  DST: {dst} | Protocol: {proto} | Size: {length} bytes")

print("\n==========================================================")
print("    CodeAlpha Basic Network Sniffer Started")
print("   Capturing Live Packets... Press CTRL + C to stop")
print("==========================================================\n")

sniff(store=False, prn=packet_callback)
