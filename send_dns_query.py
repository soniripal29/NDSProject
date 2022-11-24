from scapy.all import *


#packet from a src to local DNS server
ip_packet  = IP(src='10.10.10.10',dst='10.9.0.53')
# from a random port to DNS port
udp_packet = UDP(sport=234, dport=53,chksum=0)

qd_sec = DNSQR(qname='twysw.example.com') 
dns_packet = DNS(id=0xAAAA, qr=0, qdcount=1, qd=qd_sec)
query_packet = ip_packet/udp_packet/dns_packet

with open('dns_request.bin', 'wb') as f:
  f.write(bytes(query_packet))
  query_packet.show()
send(query_packet)
