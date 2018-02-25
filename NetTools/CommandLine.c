#include <stdio.h>
#include "CommandLine.h"
#include "Mode.h"

#ifdef WIN32
	#ifndef M_WIN_SOCK
	#define M_WIN_SOCK
		#include <winsock2.h> //struct in_addr
	#endif
#endif

#ifndef WIN32
	#include <sys/socket.h>
    #include <netinet/in.h>
#endif

extern settings_t settings;

char * general_working_mode_names[] =
{
	"--arp-scan",
	"--arp-spoofing",
	"--arp-poisoning",
	"--arp-faking",
	"--arp-silent-scan",
	"--ip-fragmentation",
	"--tcp-syn-flood"
};

char * description[]=
{
	"",
	"\t[ip-router] [ip-client]",
	"\t[ip-router] [ip-client]",
	"\t[ip-router] [ip-client] [ip-fake]",
	"[timeout in seconds]",
	"[ip-router] [ip-client]",
	"\t[ip-target] [ip-fake]"
};

void ShowLogo()
{
	printf("\n");

	printf("=======================================\n");
	printf("===== NetTools v0.2.0 by Promix17 =====\n");
	printf("=======================================\n");

	printf("\n");
}

void ShowHelp()
{
	int i;

	ShowLogo();
	printf("Usage:\n\n");
	for(i=0; i<MODE_LAST_MODE;i++)
		printf("\t%s\t%s\n", general_working_mode_names[i], description[i]);

	printf("\nParams:\n\n");

	printf("\t--dumpfile=[filename]\t(any mode)\n");
	printf("\t--found-delay=[ms]\t(arp-scan)\n");
	printf("\t--spoof-delay=[ms]\t(arp-scan)\n");
	printf("\t--arp-request\t\t(arp-spoofing)\n");
	printf("\t--arp-reply\t\t(arp-spoofing)\n");
	printf("\t--ip-router=[ip]\t(tcp-syn-flood)\n");
	printf("\t--port=[number]\t(tcp-syn-flood)\n");
	printf("\n");
}

int ParceArgs(int argc, char ** argv)
{
	int i;
	int mode_selected=-1;
	settings.dumpfile=0;
	settings.arp_scan_settings.timeout=1000;
	settings.arp_spoofing_settings.arp_spoofing_timeout=500;
	settings.arp_spoofing_settings.spoofing_mode=SPOOFING_MODE_REQUEST;
	settings.tcp_syn_flood.ip_router=0;
	settings.tcp_syn_flood.port=80;

	if(argc<2)
	{
		return -1;
	}

	for(i=1; i<argc; i++)
	{
		if(!strcmp(argv[i], general_working_mode_names[MODE_ARP_SCAN]))
		{
			settings.general_working_mode=MODE_ARP_SCAN;
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_ARP_SILENT_SCAN]))
		{
			settings.general_working_mode=MODE_ARP_SILENT_SCAN;
			if(i+1<argc)
			{
				settings.arp_scan_settings.timeout=1000*atoi(argv[i+1]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_ARP_SPOOFING]))
		{
			settings.general_working_mode=MODE_ARP_SPOOFING;
			if(i+2<argc)
			{
				settings.arp_spoofing_settings.ip_router=inet_addr(argv[i+1]);
				settings.arp_spoofing_settings.ip_client=inet_addr(argv[i+2]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_ARP_POISONING]))
		{
			settings.general_working_mode=MODE_ARP_POISONING;
			if(i+2<argc)
			{
				settings.arp_spoofing_settings.ip_router=inet_addr(argv[i+1]);
				settings.arp_spoofing_settings.ip_client=inet_addr(argv[i+2]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_ARP_FAKING]))
		{
			settings.general_working_mode=MODE_ARP_FAKING;
			if(i+3<argc)
			{
				settings.arp_spoofing_settings.ip_router=inet_addr(argv[i+1]);
				settings.arp_spoofing_settings.ip_client=inet_addr(argv[i+2]);
				settings.arp_spoofing_settings.ip_fake=inet_addr(argv[i+3]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_TCP_SYN_FLOOD]))
		{
			settings.general_working_mode=MODE_TCP_SYN_FLOOD;
			if(i+2<argc)
			{
				settings.tcp_syn_flood.ip_target=inet_addr(argv[i+1]);
				settings.tcp_syn_flood.ip_fake=inet_addr(argv[i+2]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strcmp(argv[i], general_working_mode_names[MODE_IP_FRAGMENTATION]))
		{
			settings.general_working_mode=MODE_IP_FRAGMENTATION;
			if(i+2<argc)
			{
				settings.arp_spoofing_settings.ip_router=inet_addr(argv[i+1]);
				settings.arp_spoofing_settings.ip_client=inet_addr(argv[i+2]);
			}
			else
			{
				ShowHelp();
				exit(0);
			}
			mode_selected=0;
		}
		if(!strncmp(argv[i], "--dumpfile=", strlen("--dumpfile=")))
		{
			settings.dumpfile=argv[i]+strlen("--dumpfile=");
		}
		if(!strncmp(argv[i], "--found-delay=", strlen("--found-delay=")))
		{
			settings.arp_scan_settings.timeout=atoi(argv[i]+strlen("--found-delay="));
		}
		if(!strncmp(argv[i], "--spoof-delay=", strlen("--spoof-delay=")))
		{
			settings.arp_spoofing_settings.arp_spoofing_timeout=atoi(argv[i]+strlen("--spoof-delay="));
		}
		if(!strcmp(argv[i], "--arp-request"))
		{
			settings.arp_spoofing_settings.spoofing_mode=SPOOFING_MODE_REQUEST;
		}
		if(!strcmp(argv[i], "--arp-reply"))
		{
			settings.arp_spoofing_settings.spoofing_mode=SPOOFING_MODE_REPLY;
		}
		if(!strncmp(argv[i], "--ip-router=", strlen("--ip-router=")))
		{
			settings.tcp_syn_flood.ip_router=inet_addr(argv[i]+strlen("--ip-router="));
		}
		if(!strncmp(argv[i], "--port=", strlen("--port=")))
		{
			settings.tcp_syn_flood.port=atoi(argv[i]+strlen("--port="));
		}

	}

	return mode_selected;
}