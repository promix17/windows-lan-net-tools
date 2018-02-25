#include "ArpScan.h"
#include "ArpSend.h"
#include "GeneralSettings.h"
#include "Mode.h"
#include "Loop.h"
#include "Platform.h"
#include <stdio.h>

extern local_host_t local_host;
extern settings_t settings;

void ArpScan()
{
	struct sockaddr_in addr;
	uint32_t ip=1;
	int prev_loop_working_mode=settings.loop_working_mode;
	int prev_parce_packets_mode=settings.parce_packets_mode;

	settings.loop_working_mode=LOOP_MODE_ARP_IMPORT;
	settings.parce_packets_mode=PARCE_ETHERNET|PARCE_ARP;

	StartFunction(Loop, 0);

	for(ip=1; !(htonl(ip)&local_host.net_mask->sin_addr.S_un.S_addr); ip++)
	{
		addr.sin_addr.S_un.S_addr=htonl(ip)|(local_host.net_mask->sin_addr.S_un.S_addr&local_host.local_host->sin_addr.S_un.S_addr);
		SendLegalArpRequest(&addr);
	}

	sleep(settings.arp_scan_settings.timeout);
	CloseLoop();

	settings.loop_working_mode=prev_loop_working_mode;
	settings.parce_packets_mode=prev_parce_packets_mode;
}

void ArpScanIp(uint32_t ip)
{
	struct sockaddr_in addr;
	int prev_loop_working_mode=settings.loop_working_mode;
	int prev_parce_packets_mode=settings.parce_packets_mode;

	settings.loop_working_mode=LOOP_MODE_ARP_IMPORT;
	settings.parce_packets_mode=PARCE_ETHERNET|PARCE_ARP;

	StartFunction(Loop, 0);

	addr.sin_addr.S_un.S_addr=ip;
	SendLegalArpRequest(&addr);
	
	sleep(settings.arp_scan_settings.timeout);
	CloseLoop();

	settings.loop_working_mode=prev_loop_working_mode;
	settings.parce_packets_mode=prev_parce_packets_mode;
}

void ArpSilentScan()
{
	int prev_loop_working_mode=settings.loop_working_mode;
	int prev_parce_packets_mode=settings.parce_packets_mode;

	settings.loop_working_mode=LOOP_MODE_ARP_IMPORT;
	settings.parce_packets_mode=PARCE_ETHERNET|PARCE_ARP;

	StartFunction(Loop, 0);

	sleep(settings.arp_scan_settings.timeout);

	CloseLoop();

	settings.loop_working_mode=prev_loop_working_mode;
	settings.parce_packets_mode=prev_parce_packets_mode;
}