from scapy.all import *

def packet_check(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()
        # Return True to stop sniffing after first match
        return True

def receive_icmp():
    sniff(filter="icmp", prn=packet_check, stop_filter=packet_check, store=0)
    return True

if __name__ == "__main__":
    receive_icmp()