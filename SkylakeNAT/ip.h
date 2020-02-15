#pragma once

#include <stdint.h>

#pragma pack(push, 1)
struct ip_hdr
{
public:
	enum flags
	{
		IP_RF													= 0x8000,			/* reserved fragment flag */
		IP_DF													= 0x4000,			/* dont fragment flag */
		IP_MF													= 0x2000,			/* more fragments flag */
		IP_OFFMASK												= 0x1fff,			/* mask for fragmenting bits */
	};

public:
	 /* version / header length / type of service */
	 unsigned char												_v_hl;
	 /* type of service */
	 unsigned char												_tos;
	 /* total length */
	 unsigned short												_len;
	 /* identification */
	 unsigned short												_id;
	 /* fragment offset field */								
	 unsigned short												_flags;
	 /* time to live */
	 unsigned char												_ttl;
	 /* protocol */
	 unsigned char												_proto;
	 /* checksum */
	 unsigned short												_chksum;
	 /* source and destination IP addresses */
	 unsigned int												_src;
	 unsigned int												_dest;

public:
	inline static int											IPH_V(ip_hdr* hdr)
	{
		return ((hdr)->_v_hl >> 4);
	}
	inline static int											IPH_HL(ip_hdr* hdr)
	{
		return ((hdr)->_v_hl & 0x0f);
	}
	inline static int											IPH_PROTO(ip_hdr* hdr)
	{
		return ((hdr)->_proto & 0xff);
	}
	inline static int											IPH_OFFSET(ip_hdr* hdr)
	{
		return (hdr)->_flags;
	}
	inline static int											IPH_TTL(ip_hdr* hdr)
	{
		return ((hdr)->_ttl & 0xff);
	}

public:
	static ip_hdr*												Parse(const void* packet, int size);

public:
	static const unsigned char IP_VER							= 4;
	static const unsigned char IP_HLEN							= 20;
	static const unsigned int  IP_ADDR_ANY_VALUE				= 0x00000000;
	static const unsigned int  IP_ADDR_BROADCAST_VALUE			= 0xffffffff;
	static const unsigned char IP_PROTO_ICMP					= 1;
	static const unsigned char IP_PROTO_UDP						= 17;
	static const unsigned char IP_PROTO_TCP						= 6;
	static const unsigned char IP_PROTO_IGMP					= 2;
	static const unsigned char IP_PROTO_GRE						= 47;
};
#pragma pack(pop)