#ifndef M_IP4
#define M_IP4

#include <stdint.h>
#include "Loop.h"

void ParceIp4(packet_data_t * packet_data);
uint16_t net_checksum(void * data, size_t len);

#endif