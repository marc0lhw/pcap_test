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

  int Datalen = 0;							// data 존재유무 파악
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

	ETH_header = (libnet_ethernet_hdr*)packet;			// Ethernet 정보 출력
	printf("ETH src : ");
        for(int i = 0; i<6; i++) {
                printf("%02x", ETH_header->ether_shost[i]);
                if(i<5) printf(":");
        }
        printf("\n");
	printf("ETH dst : ");
	for(int i = 0; i<6; i++) {
		printf("%02x", ETH_header->ether_dhost[i]);
		if(i<5) printf(":");
	}
	printf("\n");
	printf("ETH type : %04x ", ntohs(ETH_header->ether_type));
	if(ntohs(ETH_header->ether_type) == 0x0800)			// IP 일때  진행
		printf("	-> It's IP!\n");
	else {
		printf("\n\n");
		continue;
	}
	
	packet += sizeof(struct libnet_ethernet_hdr);			// IP 정보 출력
	IP_header = (libnet_ipv4_hdr*)packet;
        printf("IP src : %s\n", inet_ntoa(IP_header->ip_src));
	printf("IP dst : %s\n", inet_ntoa(IP_header->ip_dst));
	printf("IP protocol : %02x ", IP_header->ip_p);	
	if(IP_header->ip_p == 0x06)					// TCP 일때 진행
		printf("	-> It's TCP!\n");
	else {
		printf("\n\n");
		continue;
	}
									// IP 헤더의 len field -> Datalen 구하기
	Datalen = IP_header->ip_len - sizeof(struct libnet_ipv4_hdr) - sizeof(struct libnet_tcp_hdr);

	packet += sizeof(struct libnet_ipv4_hdr);			// TCP 정보 출력
	TCP_header = (libnet_tcp_hdr*)packet;
        printf("TCP src : %d\n", TCP_header->th_sport);
	printf("TCP dst : %d\n", TCP_header->th_dport);

	if(Datalen > 0) {						// Data 정보 출력
		packet += sizeof(struct libnet_tcp_hdr);
		printf("Data exists!		-> ");
		for (int i=0; i<16; i++, packet++)
			printf("%02x ", *packet); 
		printf("\n");
	}
	else
		printf("\n");

	printf("\n");
  }

  pcap_close(handle);
  return 0;
}





