#include "PacketBuilder.h"
#include <stdlib.h>  

void CreatePacket(packet_t * pkt)
{
	pkt->data=0;
	pkt->size=0;
}

void AddData(packet_t * pkt, void * p, size_t size)
{
	pkt->data=(uint8_t *)realloc(pkt->data, pkt->size+size);
	memcpy(&pkt->data[pkt->size], p, size);
	pkt->size+=size;
}

void DestroyPacket(packet_t * pkt)
{
	if(pkt->data) free(pkt->data);
}
