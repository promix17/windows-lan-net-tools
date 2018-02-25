#ifndef PACKET_BUILDER
#define PACKET_BUILDER

#include <stdint.h>

typedef struct packet_s
{
	uint8_t * data;
	
	int size;

} packet_t;

void CreatePacket(packet_t * pkt);
void AddData(packet_t * pkt, void * p, size_t size);
void DestroyPacket(packet_t * pkt);

#endif