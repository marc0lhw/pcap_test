#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <libnet-macros.h>
#include <libnet-headers.h>


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
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

	ETH_header = (libnet_ethernet_hdr*)packet;
	//printf("ETH dest : %x\n", ETH_header->ether_dhost);
	printf("ETH dest : ");
	for(int i = 0; i<6; i++)
		printf("%02x ", ETH_header->ether_dhost[i]);
	printf("\n");
	printf("ETH src : ");
        for(int i = 0; i<6; i++)
                printf("%02x ", ETH_header->ether_shost[i]);
        printf("\n");

	printf("ETH type : %04x \n", ntohs(ETH_header->ether_type));

	if(ntohs(ETH_header->ether_type) == 0x0800)
		printf("It's IP!\n");

	
	
  }

  pcap_close(handle);
  return 0;
}





