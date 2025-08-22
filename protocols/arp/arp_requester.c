// ---------------------------------------------------------------------------
// ARP Requester
// ---------------------------------------------------------------------------
//
// Note: ARP cache handling is not yet implemented in this version.
//
// Prerequisites for testing in a VM setup:
// 1. Add two network interfaces in the VM configuration before starting.
// 2. (Advanced approach) You can use Linux network namespaces instead of VMs.
// 3. Bring interfaces up:
//      sudo ip link set <interface_name> up
// 4. Assign an IP address to each interface:
//      sudo ip addr add 192.168.10.2/24 dev <interface_name>
// 5. Run the ARP responder on one interface and the requester on the other.
//    (Update ifreq_name with the correct interface name.)
// 6. Disable the kernel’s default ARP handling before running:
//      sudo ip link set dev <interface_name> arp off
// 7. To list available interfaces:
//      ip link show
// 8. To capture traffic on a specific interface for debugging:
//      sudo tcpdump -i <interface_name>
//
// ---------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
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


//--------------------------------------------------------------------------
//REQUEST SOCKET

void arp_req_gen(const char* str,unsigned char* mac){//str=tpa

	//creating buffer
	unsigned char* buff=(unsigned char*)malloc(42);
	memset(buff,0,42);

	//creating arp packet
	int arp_req_fd=socket(AF_PACKET,SOCK_RAW,htons(ADDRESS_RESOLUTION));
	if(arp_req_fd<0)
	{
		perror("error in socket\n");
		return;
	}

	struct arp* ar; struct eth_hdr* eth;
	eth=(eth_hdr*)buff;
	ar=(arp*)(buff+sizeof(eth_hdr));

	struct ifreq ifreq_c,hwreq,ipreq;
	memset(&ifreq_c,0,sizeof(struct ifreq));

	struct sockaddr_ll saddr_ll;
	memset(&saddr_ll,0,sizeof(struct sockaddr_ll));

	//get interface and fill sockaddr
	strncpy(ifreq_c.ifr_name,"enp0s1",IFNAMSIZ-1);

	//getting index of the interface, used in sockaddr_ll
	if((ioctl(arp_req_fd,SIOCGIFINDEX,&ifreq_c))<0)
		perror("error in SIOCGIFINDEX");

	strncpy(hwreq.ifr_name,"enp0s1",IFNAMSIZ-1);

	//getting mac/ethernet address of the interface
	if((ioctl(arp_req_fd,SIOCGIFHWADDR,&hwreq))<0)
		perror("error in SIOCGIFHWADDR");

	strncpy(ipreq.ifr_name,"enp0s1",IFNAMSIZ-1);

	//getting ip address of the interface
	if((ioctl(arp_req_fd,SIOCGIFADDR,&ipreq))<0)
		perror("error in SIOCGIFADDR");

	saddr_ll.sll_family=AF_PACKET;
	saddr_ll.sll_ifindex=ifreq_c.ifr_ifindex;
	saddr_ll.sll_halen=6;
	saddr_ll.sll_protocol = htons(ADDRESS_RESOLUTION);




	//packet fill


	//filling ethernet header
	eth->sha[0] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[0]);
	eth->sha[1] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[1]);
	eth->sha[2] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[2]);
	eth->sha[3] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[3]);
	eth->sha[4] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[4]);
	eth->sha[5] = (unsigned char)(hwreq.ifr_hwaddr.sa_data[5]);
	//alt>memcpy(eth->sha, ifreq_c.ifr_hwaddr.sa_data, 6);

	memset(eth->tha,0xFF,6);
	eth->pro=htons(ADDRESS_RESOLUTION);// the payload, whats is next in the eth frame
					   // htons required for multibyte data sent over the network, structs inside packet


					   //filling arp header
	ar->hrd=htons(ETHERNET);
	ar->pro=htons(0x0800); //the type of protocol that the ARP is resolving.ARP is used to resolve IPv4 addresses \u2192 0x0800 (for IPv4).
	ar->hln=6;
	ar->pln=4;
	//IP addresses are stored as single 32-bit integers, not as byte arrays, therefore they can be directly assigned
	ar->sha[0] = hwreq.ifr_hwaddr.sa_data[0];
	ar->sha[1] = hwreq.ifr_hwaddr.sa_data[1];
	ar->sha[2] = hwreq.ifr_hwaddr.sa_data[2];
	ar->sha[3] = hwreq.ifr_hwaddr.sa_data[3];
	ar->sha[4] = hwreq.ifr_hwaddr.sa_data[4];
	ar->sha[5] = hwreq.ifr_hwaddr.sa_data[5];
	//alt.memcpy(arp->sha, ifr->ifr_hwaddr.sa_data, 6);

	ar->spa=((struct sockaddr_in*)&(ipreq.ifr_addr))->sin_addr.s_addr;

	//arp->tha can be set to all f's as it is to be broadcasted(as will be in sockaddr_ll), 
	//but the ethernet frames payload is read only by the receiver's, and in case of arp, reciever's wont read the tha,
	// as it is supposed to be fill by them, if the next field, arp->tpa matches their own ip



	//getting tpa from the string argument passed to the module
	struct in_addr tpa;
	inet_pton(AF_INET,str,&tpa);
	ar->tpa=tpa.s_addr;
	//inet_pton(AF_INET, ...) already stores the result in network byte order.
	ar->op=htons(opcode_request);

	memset(saddr_ll.sll_addr,0xFF,6);
	//for(int i=0; i<42; i++) printf("%02x ", buff[i]); printf("\n"); printing the buffer to verify

	//printf("ar->tpa (as IP): %s\n", inet_ntoa(*(struct in_addr *)&ar->tpa));

	int len=sendto(arp_req_fd,buff,42,0,(struct sockaddr*)&saddr_ll,sizeof(struct sockaddr_ll));
	if(len<0){
		perror("error in sendto");
		return;}

	printf("packet sent successfully\n");

	// memcpy(saddr_ll.sll_addr,str,6); the kernel fills the mac address of dest when it receives the packet, u dont need to do it
	socklen_t sll_len = sizeof(struct sockaddr_ll);
	saddr_ll.sll_protocol = htons(ETH_P_ALL);

	if((bind(arp_req_fd,(struct sockaddr*)&saddr_ll,sizeof(struct sockaddr_ll)))<0)
	{         perror("binding\n"); return;}

	while(1){

		int n = recvfrom(arp_req_fd, buff, 42, 0, (struct sockaddr*)&saddr_ll, &sll_len);

		if (n < 0) {
			perror("recvfrom failed");
			continue;}
		if(ntohs(ar->op)!=opcode_reply)
			continue;
		else
			break;

	}
	printf("reply received successfully\n");

	//update cache
	close(arp_req_fd);

	printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->sha[0], eth->sha[1], eth->sha[2],
			eth->sha[3], eth->sha[4], eth->sha[5]);

	memcpy(mac,eth->tha,6);
	free(buff);
}
//----------------------------------------------------------------------------




//----------------------------------------------------------------------------
int main(){

	//receiver's ip, enp0s2 in this case
	char* str=(char*)malloc(16);

	strcpy(str,"192.168.10.2");

	unsigned char* mac=(unsigned char*)malloc(46);

	arp_req_gen(str,mac);

	free(mac);
	free(str);

	return 0;
}
