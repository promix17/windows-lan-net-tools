#ifndef CHECKSUM
#define CHECKSUM

#include <stdint.h>

uint16_t net_checksum(void * data, size_t len);
uint16_t tcp_checksum(void * data, size_t len, uint32_t ip_dst, uint32_t ip_src);

#endif