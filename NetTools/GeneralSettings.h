#ifndef GENERAL_SETTINGS
#define GENERAL_SETTINGS

#include <stdint.h>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #ifndef M_WIN_SOCK
	#define M_WIN_SOCK
		#include <winsock2.h> //struct in_addr
	#endif
#endif

typedef struct local_host_s
{
	char * device_name;

	struct sockaddr_in * local_host;
	struct sockaddr_in * net_mask;
	struct sockaddr_in * broadcast;
	struct sockaddr_in * destination;

	uint8_t mac[6];

} local_host_t;

void AddLocalHostToTheNetTopology();

#endif