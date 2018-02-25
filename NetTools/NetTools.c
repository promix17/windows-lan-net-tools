#include <stdio.h>
#include <pcap.h>
#include "GeneralSettings.h"
#include "SelectDevice.h"
#include "CommandLine.h"
#include "ArpScan.h"
#include "GetMAC.h"
#include "PcapManager.h"
#include "Loop.h"
#include "Platform.h"
#include "ShowStat.h"
#include "Mode.h"
#include "ArpSpoofing.h"
#include "IpFragmentation.h"
#include "SynFlood.h"

#pragma comment(lib, "wpcap.lib")

#ifdef WIN32

	#pragma comment(lib, "ws2_32.lib")

#endif

extern local_host_t local_host;
extern settings_t settings;

extern uint32_t mbits_per_second;

int main(int argc, char ** argv)
{
	if(ParceArgs(argc, argv))
	{
		ShowHelp();
		return 0;
	}
	
	if(select_device()) return -1;
	if(GetMac()) return -1;
	AddLocalHostToTheNetTopology();

	switch(settings.general_working_mode)
	{
	case MODE_ARP_SCAN:
		if(OpenDevice(0)) return -1;
		ArpScan();		
		CloseDevice();
		ShowNetTopology();
		break;
	case MODE_ARP_SILENT_SCAN:
		if(OpenDevice(0)) return -1;
		ArpSilentScan();		
		CloseDevice();
		ShowNetTopology();
		break;
	case MODE_ARP_SPOOFING:
		if(OpenDevice(PCAP_OPENFLAG_PROMISCUOUS)) return -1;
		ArpSpoofing();
		CloseDevice();
		break;
	case MODE_ARP_POISONING:
		if(OpenDevice(PCAP_OPENFLAG_PROMISCUOUS)) return -1;
		ArpPoisoning();
		CloseDevice();
		break;
	case MODE_ARP_FAKING:
		if(OpenDevice(PCAP_OPENFLAG_PROMISCUOUS)) return -1;
		ArpFaking();
		CloseDevice();
		break;
	case MODE_IP_FRAGMENTATION:
		if(OpenDevice(PCAP_OPENFLAG_PROMISCUOUS)) return -1;
		IpFragmentation();
		CloseDevice();
		break;
	case MODE_TCP_SYN_FLOOD:
		if(OpenDevice(0)) return -1;
		PrepareSynFlood();
		StartFunction(SynFlood, 0);	
		while(1)
		{
			sleep(800);
			printf("%d mbit per sec\n", mbits_per_second);
			mbits_per_second=0;
		}
		CloseDevice();
		break;
	}

	return 0;
}