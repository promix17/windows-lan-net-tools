#include "ShowStat.h"
#include "Topology.h"
#include <stdio.h>

void F(item_t * item)
{
	char ip1[64];
	struct sockaddr_in x;
	x.sin_addr.S_un.S_addr=item->ip;
	strcpy(ip1, inet_ntoa(x.sin_addr));
	printf("%s\t%x:%x:%x:%x:%x:%x", ip1,item->mac[0],item->mac[1],item->mac[2],item->mac[3],item->mac[4],item->mac[5]);
	if(item->is_local_host)
	{
		printf("\t LocalHost");
	}
	printf("\n");
}

void ShowNetTopology()
{
	printf("\n");
	WalkNet(F);
}