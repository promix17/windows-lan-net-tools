#include "Checksum.h"
#include "NetHeaders.h"

#ifdef WIN32
#pragma pack (push, 1)
#endif

struct ip_pseudo_s
{
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t null;
	uint8_t p;
	uint16_t len;
} 

#ifndef WIN32 
__attribute__((packed)) 
#endif

;

typedef struct ip_pseudo_s ip_pseudo_t;

#ifdef WIN32
#pragma pack ( pop)
#endif

uint16_t net_checksum(void * data, size_t len)
{
	uint32_t sum = 0;
	uint16_t * dp = (uint16_t *) data;
	uint16_t sum_s;
	int words = len >> 1;

	while( words -- )
		sum += *dp ++;

	if( len & 1 )
		sum += *(uint8_t *) dp;

	sum = (uint16_t) sum + (sum >> 16) & 0xffff;
	sum_s = (uint16_t) sum + (uint16_t)(sum >> 16);
	return sum_s != 0xffff ? ~sum_s : sum_s;
} 

uint16_t tcp_checksum(void * data, size_t len, uint32_t ip_dst, uint32_t ip_src)
{
	ip_pseudo_t pseudo;
	uint16_t s[2];
	uint32_t r;

	pseudo.ip_dst=ip_dst;
	pseudo.ip_src=ip_src;
	pseudo.len=htons(len);
	pseudo.null=0;
	pseudo.p=IP4_P_TCP;

	s[0]=net_checksum(&pseudo, sizeof(ip_pseudo_t));
	s[1]=net_checksum(data, len);

	r=s[0]+s[1];

	while (r>>16)
		r = (r & 0xFFFF)+(r >> 16);

	return r;
}