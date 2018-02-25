#ifndef MODE
#define MODE

#include <stdint.h>

typedef enum general_working_mode_e
{
	MODE_ARP_SCAN,
	MODE_ARP_SPOOFING,
	MODE_ARP_POISONING,
	MODE_ARP_FAKING,
	MODE_ARP_SILENT_SCAN,
	MODE_IP_FRAGMENTATION,
	MODE_TCP_SYN_FLOOD,
	MODE_LAST_MODE
} general_working_mode_t;

enum parce_packets_mode_e
{
	PARCE_ETHERNET=1,
	PARCE_ARP=2,
	PARCE_IP4=4,
	PARCE_TCP=8,
	PARCE_UDP=16
};

enum loop_working_mode_e
{
	LOOP_MODE_ARP_IMPORT=1,
	LOOP_MODE_ARP_SPOOFING=2,
	LOOP_MODE_IP_FRAGMENTATION=4
};

typedef struct arp_scan_settings_s
{
	
	int timeout;

} arp_scan_settings_t;

enum spoofing_modes_e
{
	SPOOFING_MODE_REQUEST,
	SPOOFING_MODE_REPLY
};

typedef struct arp_spoofing_settings_s
{
	uint32_t ip_router;
	uint32_t ip_client;
	uint32_t ip_fake;

	uint8_t  mac_client[6];
	uint8_t  mac_router[6];

	int arp_spoofing_timeout;
	int spoofing_mode;

} arp_spoofing_settings_t;

typedef struct tcp_syn_flood_s
{
	uint32_t ip_router;
	uint32_t ip_fake;
	uint32_t ip_target;

	uint8_t  mac_router[6];
	uint8_t  mac_fake[6];
	uint8_t  mac_target[6];

	uint16_t port;

} tcp_syn_flood_t;

typedef struct settings_s
{
	int general_working_mode;
	int parce_packets_mode; 
	int loop_working_mode;

	char * dumpfile;

	arp_scan_settings_t arp_scan_settings;
	arp_spoofing_settings_t arp_spoofing_settings;
	tcp_syn_flood_t tcp_syn_flood;

} settings_t;

#endif