#include <pcap.h>
#include "ip4.h"
#include "NetHeaders.h"
#include "Mode.h"
#include "GeneralSettings.h"
#include "Checksum.h"

extern settings_t settings;
extern local_host_t local_host;
extern pcap_t * fp;

#define SPLIT_SIZE 1

int SplitIp4(uint8_t * data, size_t size, uint8_t * ip4_data, ip4_header_t * ip4)
{
	int hsize=ip4_data-data;
	int dsize=ntohs(ip4->ip_len)-ip4->ip_hl*4;
	uint8_t * h1;
	uint8_t * h2;
	size_t size1;
	size_t size2;

	size1=hsize+SPLIT_SIZE*8;
	size2=dsize+hsize-SPLIT_SIZE*8;
	h1=(uint8_t *) malloc(size1);
	h2=(uint8_t *) malloc(size2);
	ip4->ip_off=htons(0|0x2000);
	ip4->ip_len=htons(ip4->ip_hl*4+SPLIT_SIZE*8);
	ip4->ip_sum=0;
	ip4->ip_sum=net_checksum((uint8_t *) ip4, sizeof(ip4_header_t));
	memcpy(h1, data, size1);
	ip4->ip_off=htons(SPLIT_SIZE|0);
	ip4->ip_len=htons(ip4->ip_hl*4+dsize-SPLIT_SIZE*8);
	ip4->ip_sum=0;
	ip4->ip_sum=net_checksum((uint8_t *) ip4, sizeof(ip4_header_t));
	memcpy(h2, data, hsize);
	memcpy(h2+hsize,data+size1, size2-hsize);
	if(pcap_sendpacket(fp, h2, size2)!=0)
	{
		printf("Error sending packet!\n");
		return -1;
	}
	if(pcap_sendpacket(fp, h1, size1)!=0)
	{
		printf("Error sending packet!\n");
		return -1;
	}

	return 0;
}

void ParceIp4(packet_data_t * packet_data)
{
	if(packet_data->next_size<sizeof(ip4_header_t))
	{
		return; //Error!
	}

	packet_data->ip4_header=(ip4_header_t *) packet_data->next_data;

	if(settings.loop_working_mode&LOOP_MODE_ARP_SPOOFING)
	{
		if(packet_data->ip4_header->ip_src.S_un.S_addr==settings.arp_spoofing_settings.ip_client&&!memcmp(packet_data->eth_header->h_dest,local_host.mac,6))
		{
			memcpy(packet_data->eth_header->h_source,local_host.mac,6);
			memcpy(packet_data->eth_header->h_dest,settings.arp_spoofing_settings.mac_router,6);
			if(pcap_sendpacket(fp, packet_data->packet_data, packet_data->packet_size)!=0)
			{
				printf("Error sending packet!\n");
				return;
			}
		}
		if(packet_data->ip4_header->ip_dst.S_un.S_addr==settings.arp_spoofing_settings.ip_client&&!memcmp(packet_data->eth_header->h_dest,local_host.mac,6))
		{
			memcpy(packet_data->eth_header->h_source,local_host.mac,6);
			memcpy(packet_data->eth_header->h_dest,settings.arp_spoofing_settings.mac_client,6);
			if(pcap_sendpacket(fp, packet_data->packet_data, packet_data->packet_size)!=0)
			{
				printf("Error sending packet!\n");
				return;
			}
		}
	}
	
	if(settings.loop_working_mode&LOOP_MODE_IP_FRAGMENTATION)
	{
		if(packet_data->ip4_header->ip_src.S_un.S_addr==settings.arp_spoofing_settings.ip_client&&!memcmp(packet_data->eth_header->h_dest,local_host.mac,6))
		{
			memcpy(packet_data->eth_header->h_source,local_host.mac,6);
			memcpy(packet_data->eth_header->h_dest,settings.arp_spoofing_settings.mac_router,6);
			
			if(packet_data->ip4_header->ip_p==IP4_P_TCP)
			{
				if(SplitIp4(packet_data->packet_data, packet_data->packet_size, ((uint8_t*)packet_data->ip4_header)+packet_data->ip4_header->ip_hl*4, packet_data->ip4_header)) return;
			}
			else
			{
				if(pcap_sendpacket(fp, packet_data->packet_data, packet_data->packet_size)!=0)
				{
					printf("Error sending packet!\n");
					return;
				}
			}
		}
		if(packet_data->ip4_header->ip_dst.S_un.S_addr==settings.arp_spoofing_settings.ip_client&&!memcmp(packet_data->eth_header->h_dest,local_host.mac,6))
		{
			memcpy(packet_data->eth_header->h_source,local_host.mac,6);
			memcpy(packet_data->eth_header->h_dest,settings.arp_spoofing_settings.mac_client,6);
			
			if(pcap_sendpacket(fp, packet_data->packet_data, packet_data->packet_size)!=0)
			{
				printf("Error sending packet!\n");
				return;
			}
		}
	}

	//LOOP_MODE_IP_FRAGMENTATION
	/*
	switch(packet_data->ip4_header->ip_p)
	{
	case IP4_P_TCP:
		if(settings.parce_packets_mode&PARCE_TCP)
		{
			//ParceArp(data+sizeof(ethhdr_t), size-sizeof(ethhdr_t));
		}
		break;
	case IP4_P_UDP:
		if(settings.parce_packets_mode&PARCE_UDP)
		{
			//ParceIp4(data+sizeof(ethhdr_t), size-sizeof(ethhdr_t));
		}
		break;
	}
	*/
}