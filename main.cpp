#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct libnet_ethernet_hdr* ETH_header;
    struct libnet_ipv4_hdr* IP_header;
    struct libnet_tcp_hdr* TCP_header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

	ETH_header = (libnet_ethernet_hdr*)packet;
	//printf("ETH dest : %x\n", ETH_header->ether_dhost);
	printf("ETH dst : ");
	for(int i = 0; i<6; i++) {
		printf("%02x", ETH_header->ether_dhost[i]);
		if(i<5) printf(":");
	}
	printf("\n");
	printf("ETH src : ");
        for(int i = 0; i<6; i++) {
                printf("%02x", ETH_header->ether_shost[i]);
		if(i<5) printf(":");
	}
        printf("\n");

	printf("ETH type : %04x ", ntohs(ETH_header->ether_type));
	if(ntohs(ETH_header->ether_type) == 0x0800)
		printf("	-> It's IP!\n");
	else {
		printf("\n");
		continue;
	}
	
	packet += sizeof(struct libnet_ethernet_hdr);
	IP_header = (libnet_ipv4_hdr*)packet;
	printf("IP dst : %s\n", inet_ntoa(IP_header->ip_dst));
	printf("IP src : %s\n", inet_ntoa(IP_header->ip_src));
	//uint32_t tmp = 0x00FF0000;
	//tmp = tmp ^ IP_header->ip_dst;
        //printf("IP dst2 : %x\n", IP_header->ip_dst);        
	//printf("IP dst3 : %x\n", tmp);

	printf("IP protocol : %02x ", IP_header->ip_p);	
	if(IP_header->ip_p == 0x06)
		printf("	-> It's TCP!\n");
	else {
		printf("\n");
		continue;
	}

	packet += sizeof(struct libnet_ipv4_hdr);
	TCP_header = (libnet_tcp_hdr*)packet;
	printf("TCP dst : %d\n", TCP_header->th_dport);
	printf("TCP src : %d\n", TCP_header->th_sport);

/*	
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       // source port 
    u_int16_t th_dport;       // destination port 
*/	

	// 패킷 길이가 남아있으면 데이터 존재 -> 데이터 출력

	printf("Data : ");
	for (int i=0; i<16; i++, packet++)
		printf("%x", *packet); 

	printf("\n");
}

  pcap_close(handle);
  return 0;
}





