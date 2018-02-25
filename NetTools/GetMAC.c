#include "GetMAC.h"
#include "GeneralSettings.h"

extern local_host_t local_host;

#ifdef WIN32

#include <windows.h>
#include <iphlpapi.h>

#pragma comment (lib, "iphlpapi.lib")

int GetMac()
{
	int i;
	ULONG adapter_info_size = 0;
	PIP_ADAPTER_INFO ptr_adapter_info = NULL;
	PIP_ADAPTER_INFO ptr_adapter_info_first = NULL;
	GetAdaptersInfo( ptr_adapter_info, &adapter_info_size );
	ptr_adapter_info_first = ptr_adapter_info = (PIP_ADAPTER_INFO) malloc(adapter_info_size);

	if(GetAdaptersInfo(ptr_adapter_info, &adapter_info_size)!= ERROR_SUCCESS)
	{	
		free(ptr_adapter_info_first);
		return -1;
	}

	while(ptr_adapter_info)
    {
		if(strstr(local_host.device_name, ptr_adapter_info->AdapterName))
		{
			if(ptr_adapter_info->AddressLength!=6)
			{
				free(ptr_adapter_info_first);
				return -1;
			}

			for(i=0; i < 6; i++)
            {
				local_host.mac[i]=(unsigned char)ptr_adapter_info->Address[i];
			}
			
			/*

				local_host.adapter_name=new char[strlen(ptr_adapter_info->AdapterName)+1];
				strcpy(local_host.adapter_name, ptr_adapter_info->AdapterName);
				local_host.dhcp_enabled=ptr_adapter_info->DhcpEnabled!=0;
				local_host.wins_enabled=ptr_adapter_info->HaveWins!=0;
				local_host.type=ptr_adapter_info->Type;
				GatewayList=ptr_adapter_info->GatewayList;
				DhcpServer=ptr_adapter_info->DhcpServer;
				PrimaryWinsServer=ptr_adapter_info->PrimaryWinsServer;
				SecondaryWinsServer=ptr_adapter_info->SecondaryWinsServer;

			*/

			free(ptr_adapter_info_first);
			return 0;
		}

		ptr_adapter_info = ptr_adapter_info->Next;
    }

	free(ptr_adapter_info_first);
	return -1;
}

#else

	!!! LINUX ERROR !!!

#endif