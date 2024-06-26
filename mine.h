#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void hextostr(uint8_t *hexarr, uint8_t *res){
        char colon[2] = ":";
	for(int i=0;i<17;){
                if(i % 3 == 0){
                        if(hexarr[i/3] < 0x10) sprintf((char*)res+i, "0%x", hexarr[i/3]);
                        else sprintf((char*)res+i, "%x", hexarr[i/3]);
                        i+=2;
                }
                else{
                        res[i] = colon[0];
                        i++;
                }
        }	
}

int GetMacAddress(const char *ifname, uint8_t *mac_addr){
	struct ifreq ifr;
       	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface Mac address - socket() failed - %m\n");
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface Mac address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	close(sockfd);
	return 0;
}
