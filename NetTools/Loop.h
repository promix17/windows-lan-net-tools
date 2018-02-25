#ifndef LOOP
#define LOOP

#include "NetHeaders.h"

typedef struct packet_data_s
{
	uint8_t * packet_data;
	size_t packet_size;

	ethhdr_t * eth_header;
	size_t eth_size;

	ip4_header_t * ip4_header;
	size_t ip4_size;

	arp_t * arp;
	size_t arp_size;

	void * next_data;
	size_t next_size;

} packet_data_t;

void Loop(void *p);
void CloseLoop();

#endif