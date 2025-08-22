# ARP Implementation (RFC 826)

This folder contains a simple **ARP (Address Resolution Protocol) implementation** in C, following [RFC 826](https://datatracker.ietf.org/doc/html/rfc826). It demonstrates low-level packet handling using raw sockets on Linux.  

## Files

- `arp_requester.c` – Sends an ARP request to resolve the MAC address of a given IPv4 address.  
- `arp_responder.c` – Listens for ARP requests on a network interface and responds with the correct MAC address.  

## Features

- Constructs Ethernet and ARP headers manually.  
- Broadcasts ARP requests and captures replies.  
- Sends ARP replies for requests targeted to the host interface.  
- Uses raw sockets (`AF_PACKET`) for direct packet access.  

## Notes / Limitations

- ARP cache functionality is not implemented.  
- Interface names are currently hardcoded in the examples.  
- Kernel ARP should be disabled for proper testing.  
- Tested on Linux using VM or multiple network interfaces.  

## Usage 

1. Disable kernel ARP on the interface:
   sudo ip link set dev <interface_name> arp off
   Run the responder on one interface.

2.Run the requester on another interface with the target IP set.

3.Monitor ARP traffic (optional) using:
sudo tcpdump -i <interface_name>
