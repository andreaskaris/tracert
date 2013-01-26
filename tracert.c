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

#define MAX_PACKET_SIZE 100  

typedef double u_sec; //microseconds
typedef struct { 
  u_sec rtt; 
  unsigned short ttl; 
  unsigned short seq_num; 
  unsigned short tot_len;
  char *saddr;
  char *icmp_reply;
} ping;

int send_ping(const char * destination, unsigned short icmp_id, unsigned short icmp_seq_no, unsigned short ttl, ping *p);
unsigned short in_checksum(unsigned short *addr, int len);
 
int main(int argc, char *argv[]) {
  ping p;
  unsigned short seq_no;

  srand ( time(NULL) );
  unsigned short id = rand();
  unsigned short ttl = 1;
  for(seq_no=1;seq_no <= 10;seq_no++) {
    ttl = seq_no;
    send_ping(argv[1], id, seq_no, ttl, &p);
   
    printf("%d bytes from %s: icmp_seq=%d, ttl=%d, time=%.6f ms\n", 
	   p.tot_len,
	   p.saddr,
	   p.seq_num,
	   p.ttl,
	   p.rtt
	   );

    usleep(1000000);
  }

  return 0;
}

int send_ping(const char * destination, unsigned short icmp_id, unsigned short icmp_seq_no, unsigned short ttl, ping *p) {
  int sock;

  //src and dst
  //int nsource = inet_addr(source);
  int ndestination = inet_addr(destination);

  //round-trip time for one packet in ms
  double rtt;
  struct timespec ping_start, ping_end;

  //for packet
  char * packet;
  struct iphdr * ip_header; 
  struct icmphdr * icmp_header;

  //where do we send (yes, we have to provide dst twice, here and in ip_header)
  struct sockaddr_in dst;
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ndestination;

  //allocate memory for packet
  packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
  ip_header = (struct iphdr *) packet;
  icmp_header = (struct icmphdr *) (packet + sizeof(struct iphdr));

  //ip header configuration, see http://tools.ietf.org/html/rfc791
  ip_header->version = 4;
  ip_header->ihl = 5; //internet header length in byte
  ip_header->tos = 0;
  ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr); //total length
  ip_header->id = random();
  ip_header->frag_off = 0;
  ip_header->ttl = ttl; 
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
  
  //create socket
  if( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ) {
    perror("Error opening socket");
    exit(1);
  }

  //do NOT automatically add an IP header; we already defined on
  int is_header_included = 1; //do NOT include header
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &is_header_included, sizeof(int));

  //send out
  clock_gettime(CLOCK_REALTIME, &ping_start);
  if( sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *) &dst, sizeof(dst)) == -1 ) {
    perror("Sending icmp");
    exit(1);
  }

  //get reply; we write back to packet, so all pointers now point to the reply
  if( recv(sock, packet, ip_header->tot_len, 0) == -1 ) {
    perror("Receiving answer");
    exit(1);
  }
  clock_gettime(CLOCK_REALTIME, &ping_end);
  rtt = (ping_end.tv_sec - ping_start.tv_sec) * 1000
    + 
    (ping_end.tv_nsec - ping_start.tv_nsec) / 1E6;

  struct in_addr saddr = { ip_header->saddr  };
  p->seq_num = icmp_header->un.echo.sequence;
  p->ttl = ip_header->ttl;
  p->rtt = rtt;
  p->icmp_reply = packet;
  p->tot_len = ntohs(ip_header->tot_len);
  p->saddr = inet_ntoa(saddr);

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
