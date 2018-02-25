#include <stdio.h>
#include <pcap.h>
#include "GeneralSettings.h"
#include "SelectDevice.h"

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #ifndef M_WIN_SOCK
	#define M_WIN_SOCK
		#include <winsock2.h> //struct in_addr
	#endif
#endif

extern local_host_t local_host;

#define IPTOSBUFFERS    12

char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif

    if(getnameinfo(sockaddr, sockaddrlen, address, addrlen, NULL, 0, NI_NUMERICHOST) != 0) address = NULL;

    return address;
}

int select_device()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *a;
	char ip6str[128];
  
	printf("\n");

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n\n", errbuf);
        return -1;
    }
  
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s\n\n", ++i, d->name);
        if (d->description)
		{
            printf("\t(%s)\n\n", d->description);
		}
        else
		{
            printf("\t(No description available)\n\n");
		}
    }
    
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d): ",i);
    scanf_s("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    for(d=alldevs, i=0; i<inum-1; d=d->next, i++);
    
	local_host.device_name=(char *)malloc(strlen(d->name)+1);
	strcpy(local_host.device_name, d->name);
	
	i=0;
	
	for(a=d->addresses; a; a=a->next)
	{		
		printf("\n\tEntry #%d\n\n", ++i);
		printf("\t\tAddress Family: #%d\n",a->addr->sa_family);
  
		switch(a->addr->sa_family)
		{
		case AF_INET:
			printf("\t\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\t\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\t\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\t\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\t\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\t\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\t\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;
		default:
			printf("\t\tAddress Family Name: Unknown\n");
			break;
		}
	}

	printf("\nEnter the entry number (1-%d): ",i);
    scanf_s("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nEntry number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    for(a=d->addresses, i=0; i<inum-1; a=a->next, i++);

	if(a->addr->sa_family!=AF_INET)
	{
		printf("\nUnsupported family type.\n\n");
        pcap_freealldevs(alldevs);
        return -1;
	}

	if(a->addr)
	{
		local_host.local_host=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		*local_host.local_host=*((struct sockaddr_in *)a->addr);
	}
	else 
	{
		local_host.local_host=0;
	}			
	if(a->netmask)
	{
		local_host.net_mask=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		*local_host.net_mask=*((struct sockaddr_in *)a->netmask);
	}
	else 
	{
		local_host.net_mask=0;	
	}
	if(a->broadaddr)
	{
		local_host.broadcast=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		*local_host.broadcast=*((struct sockaddr_in *)a->broadaddr);
	}
	else 
	{
		local_host.broadcast=0;
	}
	if(a->dstaddr)
	{
		local_host.destination=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		*local_host.destination=*((struct sockaddr_in *)a->dstaddr);
	}
	else 
	{
		local_host.destination=0;
	}

	printf("\n");

    pcap_freealldevs(alldevs);

	return 0;
}