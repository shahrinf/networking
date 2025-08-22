/*
 * ARP Responder (RFC 826 implementation)
 * --------------------------------------
 * This program listens for ARP requests on a specified network interface
 * and responds with the corresponding MAC address if the target IP matches
 * the interface’s IP. It manually constructs and modifies Ethernet + ARP
 * headers to send the ARP reply over a raw socket.
 *  - ARP cache management is not implemented in this version
 *  - Interface name is currently hardcoded ("enp0s2")
 *  - Only handles a single ARP request in this example
 *  - Ensure kernel ARP is disabled on this interface when testing
 */

#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#define ADDRESS_RESOLUTION 0x0806
#define opcode_request 1
#define opcode_reply 2
#define ETHERNET 1



//no data segment or application layer protocol header for arp ethernet frame

//ethernet header
typedef struct __attribute__((packed)) eth_hdr{
	unsigned char tha[6];
	unsigned char sha[6];
	unsigned short pro; //=0x0806 :this frame is an ARP packet
}eth_hdr;


typedef struct __attribute__((packed)) arp{
	u_int16_t hrd;//=1 :ethernet
	u_int16_t pro;//=0x0800 :resolving ipv4
	unsigned char hln;//=6 :ethernet address
	unsigned char pln;//=4
	u_int16_t op;//=1 :request
	unsigned char sha[6];
	u_int32_t spa;//4bytes
	unsigned char tha[6];
	u_int32_t tpa;//4bytes
}arp;

//------------------------------------------------------------------





//----------------------------------------------------------------------------
//ARP_RESPONDER
void arp_responder(){
	//creating buffer
	unsigned char* buff=(unsigned char*)malloc(42);
	memset(buff,0,42);

	//creating arp packet
	int arp_resp_fd=socket(AF_PACKET,SOCK_RAW,htons(ADDRESS_RESOLUTION));
	if(arp_resp_fd<0)
	{
		perror("error in resp socket\n");
		return;
	}


	struct ifreq ifreq_c,hwreq,ipreq;
	memset(&ifreq_c,0,sizeof(struct ifreq));

	struct sockaddr_ll saddr_ll;
	memset(&saddr_ll,0,sizeof(struct sockaddr_ll));

	strncpy(ifreq_c.ifr_name,"enp0s2",IFNAMSIZ-1);

	//getting index of the interface, used in sockaddr_ll
	if((ioctl(arp_resp_fd,SIOCGIFINDEX,&ifreq_c))<0)
		perror("error in SIOCGIFINDEX");

	strncpy(hwreq.ifr_name,"enp0s2",IFNAMSIZ-1);

	//getting mac/ethernet address of the interface
	if((ioctl(arp_resp_fd,SIOCGIFHWADDR,&hwreq))<0)
		perror("error in SIOCGIFHWADDR");

	strncpy(ipreq.ifr_name,"enp0s2",IFNAMSIZ-1);

	//getting ip address of the interface
	if((ioctl(arp_resp_fd,SIOCGIFADDR,&ipreq))<0)
		perror("error in SIOCGIFADDR");

	//printf("Interface IP address: %s\n", inet_ntoa(((struct sockaddr_in *)&ifreq_c.ifr_addr)->sin_addr));

	saddr_ll.sll_family=AF_PACKET;
	saddr_ll.sll_ifindex=ifreq_c.ifr_ifindex;
	saddr_ll.sll_halen=6;
	saddr_ll.sll_protocol = htons(ADDRESS_RESOLUTION);

	//packet will be received and modified, no need to refill it, therefore no call to packet_fill()


	//binding not required, but if u want requests to come from a particular iterface, eg. wlan0, then required
	//binding the sockaddr_ll to the socket
	if((bind(arp_resp_fd,(struct sockaddr*)&saddr_ll,sizeof(struct sockaddr_ll)))<0)
	{         perror("binding\n"); return;}


	struct sockaddr_ll saddr_ll2;
	memset(&saddr_ll2,0,sizeof(struct sockaddr_ll));

	socklen_t sll_len = sizeof(struct sockaddr_ll);
	int n = recvfrom(arp_resp_fd, buff, 42, 0, (struct sockaddr*)&saddr_ll2, &sll_len);

	if (n < 0) {
		perror("recvfrom failed\n");
		close(arp_resp_fd);
		return;
	}
	printf("Received ARP packet of size %d bytes\n", n);

	fflush(stdout);

	//printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	//                       ifreq_c.ifr_hwaddr.sa_data[0],  ifreq_c.ifr_hwaddr.sa_data[1],  ifreq_c.ifr_hwaddr.sa_data[2],
	//                     ifreq_c.ifr_hwaddr.sa_data[3],  ifreq_c.ifr_hwaddr.sa_data[4],  ifreq_c.ifr_hwaddr.sa_data[5]);

	//parsing the received socket
	struct eth_hdr* eth=(eth_hdr*)buff;
	struct arp* ar=(arp*)(buff+sizeof(eth_hdr));

	if (ar->op == htons(opcode_request) && ar->tpa == ((struct sockaddr_in*)&ipreq.ifr_addr)->sin_addr.s_addr)
	{// sin_addr.s_addr is an in_addr_t, i.e., a uint32_t, and it is stored in network byte order in the structure.

		if (ntohs(eth->h_proto) == ETH_P_ARP){ // this if is redundant since saddr_ll already has sll_protocol = htons(ADDRESS_RESOLUTION) so only ARP packets ar received

			//update cache and 
			//modify the packet
			ar->op=htons(opcode_reply);

			//switch tha,tpa with sha,spa
			u_int32_t prev_spa=ar->spa;
			ar->spa=ar->tpa;
			ar->tpa=prev_spa;
			//since tpa,spa are integers, direct assignment is ok

			memcpy(eth->tha,eth->sha,6);
			memcpy(eth->sha, hwreq.ifr_hwaddr.sa_data, 6);

			memcpy(ar->tha,ar->sha,6);
			memcpy(ar->sha, hwreq.ifr_hwaddr.sa_data, 6);

			memcpy(saddr_ll.sll_addr,ar->tha,6);

			while(1){
				int len=sendto(arp_resp_fd,buff,42,0,(struct sockaddr*)&saddr_ll,sizeof(struct sockaddr_ll));
				if(len<0)
					perror("error in sendto\n");



			}
		}}
	free(buff);
	close(arp_resp_fd);
}
//----------------------------------------------------------------------------



//------------------------------------------------------------------------


int main(){
	arp_responder();

	return 0;
}
