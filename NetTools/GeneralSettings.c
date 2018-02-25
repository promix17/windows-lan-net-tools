#include "Topology.h"
#include "GeneralSettings.h"

local_host_t local_host;

void AddLocalHostToTheNetTopology()
{
	AddItem(local_host.local_host->sin_addr.S_un.S_addr, local_host.mac, 1);
}