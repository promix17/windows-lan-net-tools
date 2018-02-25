#ifndef M_NET_HEADERS
#define M_NET_HEADERS

#include <stdint.h>

#ifdef WIN32
	#ifndef M_WIN_SOCK
	#define M_WIN_SOCK
		#include <winsock2.h> //struct in_addr
	#endif
#endif

#ifndef WIN32
	// XZ
#endif


#ifdef WIN32
#pragma pack (push, 1)
#endif

//Ethernet

#define ETH_ALEN        6 

#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */

struct ethhdr_s 
{
		unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
		unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
		uint16_t	    h_proto;				/* packet type ID field */
} 

#ifndef WIN32 
__attribute__((packed)) 
#endif

;

typedef struct ethhdr_s ethhdr_t;

#define IP4_P_TCP 6	
#define IP4_P_UDP 17

struct ip4_header_s
{
   uint8_t        ip_hl:4, 
                  ip_v:4;
   uint8_t        ip_tos;
   uint16_t       ip_len;
   uint16_t       ip_id;
   uint16_t       ip_off;
   uint8_t        ip_ttl;
   uint8_t        ip_p;
   uint16_t       ip_sum;
   struct in_addr ip_src;
   struct in_addr ip_dst;
}

#ifndef WIN32 
__attribute__((packed)) 
#endif

;

typedef struct ip4_header_s ip4_header_t;

struct tcp_header_s 
{
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;  
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
	#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
	#  endif
	uint16_t window;  
	uint16_t check;
	uint16_t urg_ptr;
}

#ifndef WIN32 
__attribute__((packed)) 
#endif
	
;

typedef struct tcp_header_s tcp_header_t;

struct udp_header_s 
{
	uint16_t s_port;
	uint16_t d_port;
	uint16_t lenght;
	uint16_t checksum;
} 

#ifndef WIN32 
__attribute__((packed)) 
#endif

;

typedef struct udp_header_s udp_header_t;

#define ARP_REQUEST 1
#define ARP_RESPONSE 2
#define ARP_P_ETH 1

struct arp_s
{
	uint16_t hardware_type;  //Ethernet = 0x0001
	uint16_t protocol_type;  //IP = 0x0800
	uint8_t hardware_size;     // = 6
	uint8_t protocol_size;     // = 4
	uint16_t opcode;         // 0x0001 = request, 0x0002 = response
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t taget_mac[6];
	uint8_t taget_ip[4];
}

#ifndef WIN32 
__attribute__((packed)) 
#endif

;

typedef struct arp_s arp_t;


#ifdef WIN32
#pragma pack ( pop)
#endif

#endif