#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>


#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518
#define IPV6_LEN 40

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
typedef unsigned char IPv6Header[IPV6_HEADER_LEN];
extern int errno;

unsigned short in_cksum(unsigned short *addr,int len)
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
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}



int main()
{
  int sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50];
  struct sockaddr_ll destAddr;
  short int etherTypeT = htons(0x8200);

  /* Configura MAC Origem e Destino */
  MacAddress localMac = {0x00, 0x0B, 0xCD, 0xA8, 0x6D, 0x91};
  MacAddress destMac = {0x00, 0x17, 0x9A, 0xB3, 0x9E, 0x16};

  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados. Eh necess�rio conferir este valor. */
  memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

  /* Cabecalho Ethernet */
  memcpy(buffer, destMac, MAC_ADDR_LEN); // destino
  memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN); // origem
  memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT)); // tipo

  /* Cabecalho IPv6 */
  unsigned char firstLine[4] = {0x60, 0x00, 0x00, 0x00};
  unsigned char payloadLength[2] = {0x14}; // cabecalho tcp
  unsigned char nextHeader = {0x06};
  unsigned char hopLimit = {0x0F};
  unsigned char ipOrigem[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char ipDestino[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  IPv6Header ipv6 = {firstLine[0], firstLine[1], firstLine[2], firstLine[3],
                     payloadLength[0], payloadLength[1], nextHeader, hopLimit, 
                     ipOrigem[0],  ipOrigem[1], ipOrigem[2], ipOrigem[3], ipOrigem[4], ipOrigem[5], ipOrigem[6], ipOrigem[7], ipOrigem[8], ipOrigem[9], ipOrigem[10], ipOrigem[11], ipOrigem[12], ipOrigem[13], ipOrigem[14], ipOrigem[15],
                     ipDestino[0], ipDestino[1], ipDestino[2], ipDestino[3], ipDestino[4], ipDestino[5], ipDestino[6], ipDestino[7], ipDestino[8], ipDestino[9], ipDestino[10], ipDestino[11], ipDestino[12], ipDestino[13], ipDestino[14], ipDestino[15]}; 


  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons (60);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl (0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = in_checksum (iphdr, tcphdr);



  /* Add some data */
  memcpy((buffer+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

  while(1) {
    /* Envia pacotes de 64 bytes */
    if((retValue = sendto(sockFd, buffer, 64, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }
    printf("Send success (%d).\n", retValue);
  }
}

/*
buffer = mac destino + mac origem + tipo + ipv6 (next header = 6 + ...) + tcp
*/