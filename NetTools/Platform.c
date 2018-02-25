#include "Platform.h"

#ifdef WIN32

#include <windows.h>

int StartFunction(void * f, void * p)
{
	HANDLE hThread=CreateThread(0,0,(LPTHREAD_START_ROUTINE) f,p,0,0); 

	if(hThread==0)
	{		
		return -1;
	}
	else 
	{
		CloseHandle(hThread);
		return 0;
	}
}

void sleep(int ms)
{
	Sleep(ms);
}

#else

	!!! Linux Error !!!

#endif