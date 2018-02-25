#ifndef ARP_SEND
#define ARP_SEND

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
	#ifndef M_WIN_SOCK
	#define M_WIN_SOCK
		#include <winsock.h>
	#endif
#endif

int SendLegalArpRequest(struct sockaddr_in * addr);

int SendSpoofArpReplies();
int SendSpoofArpRequests();
int SendFakeArpReply();
int SendPoisonArpPacket();

#endif