#ifndef TOPOLOGY
#define TOPOLOGY

#include <pcap.h>
#include <stdint.h>

typedef struct item_s
{
	uint32_t ip;
	uint8_t mac[6];
	int is_local_host;
	struct item_s * next;
} item_t;

void AddItem(uint32_t ip, uint8_t * mac, int is_local_host);
item_t * FindItem(uint32_t ip);
void WalkNet(void (*f)(item_t * item));

#endif