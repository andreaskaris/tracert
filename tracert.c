#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <time.h>
#include <strings.h>

typedef long int u_sec;
typedef struct { 
  u_sec rrt; 
  unsigned short ttl; 
  unsigned short seq_num; 
} ping;

int send_ping(const char * destination, unsigned short icmp_id, unsigned short icmp_seq_no, ping *p);
unsigned short in_checksum(unsigned short *addr, int len);
 
int main(int argc, char *argv[]) {
  ping p;
  unsigned short seq_no;

  srand ( time(NULL) );
  unsigned short id = rand();
  for(seq_no=1;seq_no <= 10;seq_no++) { 
    send_ping(argv[1], id, seq_no, &p);
  }

  return 0;
}

int send_ping(const char * destination, unsigned short icmp_id, unsigned short icmp_seq_no, ping *p) {
  int sock;
  //int nsource = inet_addr(source);
  int ndestination = inet_addr(destination);
  char * packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
  unsigned short packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr);
  struct iphdr * ip_header = (struct iphdr *) packet;
  struct icmphdr * icmp_header = (struct icmphdr *) (packet + sizeof(struct iphdr));

  ip_header->version = 4;
  ip_header->ihl = 5; //internet header length in byte
  ip_header->tos = 0;
  ip_header->tot_len = packet_size; //total length
  ip_header->id = htons(random());
  ip_header->frag_off = 0;
  ip_header->ttl = 255;
  ip_header->protocol = IPPROTO_ICMP;
  ip_header->check = 0; 
  //ip_header->saddr = nsource; //we don't need a source address - this is actually set automatically by the socket
  ip_header->daddr = ndestination;

  ip_header->check = in_checksum((unsigned short *) ip_header, sizeof(struct iphdr));

  //set icmp header, see http://tools.ietf.org/html/rfc792
  icmp_header->type = ICMP_ECHO; //type 8
  icmp_header->code = 0; //0 by default
  icmp_header->checksum = 0; //0 for computation
  icmp_header->un.echo.id = icmp_id; //funcions as "port number"
  icmp_header->un.echo.sequence = icmp_seq_no; //sequence number

  icmp_header->checksum = in_checksum((unsigned short *) icmp_header, sizeof(struct icmphdr));

  if( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ) {
    perror("Error opening socket");
    exit(1);
  }

  /* 
   *  IP_HDRINCL must be set on the socket so that
   *  the kernel does not attempt to automatically add
   *  a default ip header to the packet
   */
  int optval;
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

  struct sockaddr_in dst;
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ndestination;
  if( sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *) &dst, sizeof(dst)) == -1 ) {
    perror("Sending icmp");
    exit(1);
  }

  printf("sizeof: %d\n", packet_size);

  bzero(packet, packet_size); //reset packet to 0
  if( recv(sock, packet, sizeof(struct iphdr) + sizeof(struct icmphdr), 0) == -1 ) {
    perror("Receiving answer");
    exit(1);
  }
  //left off here
  printf("%d bytes from %s: icmp_seq=%d, ttl=%d, time=%.3f ms\n", ip_header->tot_len, ip_header->saddr, icmp_header->un.echo.sequence, 64, 0.123); 

  return 0;
}

/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 */
unsigned short in_checksum(unsigned short *addr, int len)
{
  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;
  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
  sum += (sum >> 16);               /* add carry */
  answer = ~sum;              /* truncate to 16 bits */
  return (answer);
}
