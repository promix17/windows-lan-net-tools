#include "Ethernet.h"
#include "NetHeaders.h"
#include "Mode.h"
#include "Arp.h"
#include "ip4.h"
#include "Loop.h"

extern settings_t settings;

void ParceEthernet(packet_data_t * packet_data)
{
	if(packet_data->packet_size<sizeof(ethhdr_t))
	{
		return; //Error!
	}

	packet_data->eth_header=(ethhdr_t *) packet_data->packet_data;

	packet_data->next_data=packet_data->packet_data+sizeof(ethhdr_t);
	packet_data->next_size=packet_data->packet_size-sizeof(ethhdr_t);

	switch(ntohs(packet_data->eth_header->h_proto))
	{
	case ETH_P_ARP:
		if(settings.parce_packets_mode&PARCE_ARP)
		{
			ParceArp(packet_data);
		}
		break;
	case ETH_P_IP:
		if(settings.parce_packets_mode&PARCE_IP4)
		{
			ParceIp4(packet_data);
		}
		break;
	}
}