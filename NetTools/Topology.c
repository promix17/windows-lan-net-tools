#include "Topology.h"
#include <stdio.h>

item_t * net=0;

item_t * FindItem(uint32_t ip)
{
	item_t * cur;
	cur=net;

	if(!cur) 
		return 0;
	do
	{
		if(cur->ip==ip)
			return cur;

	} while(cur=cur->next);

	return 0;
}

void WalkNet(void (*f)(item_t * item))
{
	item_t * cur;
	cur=net;

	if(!cur) 
		return;
	do
	{
		f(cur);
	} while(cur=cur->next);
}

void AddItem(uint32_t ip, uint8_t * mac, int is_local_host)
{
	item_t * item;

	if(FindItem(ip))
		return;

	item=(item_t *) malloc(sizeof(item_t));
	item->ip=ip;
	memcpy(item->mac,mac, 6);
	item->is_local_host=is_local_host;
	item->next=net;
	net=item;
}

