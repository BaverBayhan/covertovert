from scapy.all import *

def packet_check(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()

def receive_icmp():
    sniff(filter="icmp", prn=packet_check)

if __name__ == "__main__":
    receive_icmp()
