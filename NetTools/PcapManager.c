#include <pcap.h>
#include "PcapManager.h"
#include "GeneralSettings.h"

extern local_host_t local_host;

pcap_t * fp=0;

int OpenDevice(int flags)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if((fp=pcap_open(local_host.device_name,65536, flags, 1, NULL, errbuf))==0)
    {
		printf("Error! %s\n", errbuf);
		return -1;
    }
	return 0;
}

void CloseDevice()
{
	if(fp) pcap_close(fp);
	fp=0;
}