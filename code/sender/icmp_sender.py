from scapy.all import *

def send_icmp(destination_ip):
    packet = IP(dst=destination_ip, ttl=1) / ICMP()
    send(packet)


if __name__ == "__main__":
    ip_addr = "receiver"
    send_icmp(ip_addr)
