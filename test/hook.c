#include <ws2spi.h>
#include <windows.h>
#include <stdio.h>

#define ZERO(__a) ZeroMemory(&__a, sizeof(__a))
#define NPROTOCOLS 100

int main2(int argc, char * argv[])
{

	HMODULE hMswsock=LoadLibrary(L"mswsock.dll");
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pDataSection, pCodeSection;
	LPWSPPROC_TABLE SockProcTable;
	WSPDATA _1;
	WSPUPCALLTABLE _2 = { 0 };
	WSPPROC_TABLE _3 = { 0 };
	LPWSPSTARTUP _WSPStartup = GetProcAddress(hMswsock, "WSPStartup");
	int res, err, n = NPROTOCOLS*sizeof(WSAPROTOCOL_INFOW), i, tcpproto[] = { IPPROTO_TCP, 0}, c=0;
	WSAPROTOCOL_INFOW protocols[NPROTOCOLS];
	UINT_PTR addr;
	
	if(!hMswsock)
		return 0;
	ZERO(_1);
	ZERO(_2);
	ZERO(_3);
	ZERO(protocols);
	
	res = WSCEnumProtocols(tcpproto, protocols, &n, &err);
	for(i = 0; i<res; i++) {
		if(	protocols[i].iProtocol == IPPROTO_TCP && 
			protocols[i].iAddressFamily == AF_INET)
			break;
	}
	res = _WSPStartup(MAKEWORD(2,2), &_1, protocols +i, _2, &_3);

	pDosHeader=(PIMAGE_DOS_HEADER)hMswsock;
	pNtHeaders=(PIMAGE_NT_HEADERS)((PBYTE)pDosHeader->e_lfanew + (UINT_PTR)pDosHeader);

	// The code ('.text') section is always first
	pCodeSection = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders+sizeof(IMAGE_NT_HEADERS));
	// We also need to find '.data' section. It could be 3rd or 4th. 
	for(i=1; i<pNtHeaders->FileHeader.NumberOfSections; i++) {
		pDataSection=(PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders
			+sizeof(IMAGE_NT_HEADERS) + 
			i*sizeof(IMAGE_SECTION_HEADER));	
		if(!strcmp(pDataSection->Name, ".data"))
			break;
		else pDataSection = 0;
	}

	for(i = 0; i<pDataSection->Misc.VirtualSize; i+=sizeof(UINT_PTR)) {
		addr = *((PUINT_PTR)((PBYTE)hMswsock+pDataSection->VirtualAddress+i));
		if((LPVOID)addr > pCodeSection && (LPVOID)addr < pCodeSection+(UINT_PTR)pCodeSection->Misc.VirtualSize) {
			c++;
		} else c=0;
		if(c==30) {
			SockProcTable = (LPWSPPROC_TABLE)((PBYTE)hMswsock+pDataSection->VirtualAddress+i-29*sizeof(UINT_PTR));
			break;
		}
	}

	printf("WSPSend: 0x%p real: 0x%p\n", SockProcTable->lpWSPSend, _3.lpWSPSend);
	printf("WSPSendTo: 0x%p real: 0x%p\n", SockProcTable->lpWSPSendTo, _3.lpWSPSendTo);
	printf("WSPRecv: 0x%p real: 0x%p\n", SockProcTable->lpWSPRecv, _3.lpWSPRecv);
	printf("WSPRecvFrom: 0x%p real: 0x%p\n", SockProcTable->lpWSPRecvFrom, _3.lpWSPRecvFrom);

	return 0;
}