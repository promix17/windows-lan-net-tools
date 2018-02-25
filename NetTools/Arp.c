#include "NetHeaders.h"
#include "Arp.h"
#include "Mode.h"
#include "Topology.h"

extern settings_t settings;

void ParceArp(packet_data_t * packet_data)
{
	uint32_t ip;

	if(packet_data->next_size<sizeof(arp_t))
	{
		return; //Error!
	}

	if(settings.loop_working_mode&LOOP_MODE_ARP_IMPORT)
	{
		packet_data->arp=(arp_t *) packet_data->next_data;
		if(ntohs(packet_data->arp->opcode)==ARP_RESPONSE)
		{
			memcpy(&ip, packet_data->arp->sender_ip, 4);
			AddItem(ip, packet_data->arp->sender_mac, 0);
			memcpy(&ip, packet_data->arp->taget_ip, 4);
			AddItem(ip, packet_data->arp->taget_mac, 0);
		}
		if(ntohs(packet_data->arp->opcode)==ARP_REQUEST)
		{
			memcpy(&ip, packet_data->arp->sender_ip, 4);
			AddItem(ip, packet_data->arp->sender_mac, 0);
		}		
	}
}