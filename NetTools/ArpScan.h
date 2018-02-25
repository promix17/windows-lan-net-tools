#ifndef ARP_SCAN
#define ARP_SCAN

#include <stdint.h>

void ArpScan();
void ArpScanIp(uint32_t ip);
void ArpSilentScan();

#endif