#include "ip.h"
#include <WinSock2.h>

ip_hdr* ip_hdr::Parse(const void* packet, int size) {
	ip_hdr* iphdr = (ip_hdr*)packet;
	if (NULL == iphdr)
		return NULL;
	if (IPH_V(iphdr) != ip_hdr::IP_VER)
		return NULL;
	int iphdr_hlen = 4 * IPH_HL(iphdr);
	if (iphdr_hlen > size)
		return NULL;
	if (iphdr_hlen < IP_HLEN)
		return NULL;
	int ttl = IPH_TTL(iphdr);
	if (ttl <= 0)
		return NULL;
	/* all ones (broadcast) or all zeroes (old skool broadcast) */
	if ((~iphdr->_dest == IP_ADDR_ANY_VALUE) || (iphdr->_dest == IP_ADDR_ANY_VALUE))
		return NULL;
	if ((~iphdr->_src == IP_ADDR_ANY_VALUE) || (iphdr->_src == IP_ADDR_ANY_VALUE))
		return NULL;
	int ip_proto = IPH_PROTO(iphdr);
	if (ip_proto == IP_PROTO_UDP ||
		ip_proto == IP_PROTO_TCP ||
		ip_proto == IP_PROTO_ICMP ||
		ip_proto == IP_PROTO_GRE)
		return iphdr;
	return NULL;
}