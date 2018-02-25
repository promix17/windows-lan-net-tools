#include <pcap.h>
#include "Loop.h"
#include "Ethernet.h"
#include "Mode.h"

extern pcap_t * fp;
extern settings_t settings;

int loop_exit=0;

void CloseLoop()
{
	loop_exit=1;
}

void Loop(void *p)
{
	int res;
	struct pcap_pkthdr * header;
	uint8_t * pkt_data;
	packet_data_t packet;
	pcap_dumper_t * dumpfile;

	loop_exit=0;

	if(settings.dumpfile)
		dumpfile = pcap_dump_open(fp, settings.dumpfile);
	
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{ 
		if(loop_exit) break;

        if(res == 0)
            continue;

		if(settings.dumpfile)
		{
			pcap_dump(dumpfile, header, pkt_data);
		}

		packet.packet_data=pkt_data;
		packet.packet_size=header->len;

		if(settings.parce_packets_mode&PARCE_ETHERNET) 
		{
			ParceEthernet(&packet);
		}
    }

    if(settings.dumpfile)
		pcap_dump_close(dumpfile);

    if(res == -1 && !loop_exit)
	{
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
    }    
}