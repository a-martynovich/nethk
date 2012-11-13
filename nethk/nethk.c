/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	handlers.c
 * purpose:		WinAPI WSP* functions interception
 */

#include <stdint.h>
#include <ws2spi.h>
#include "mhook/mhook.h"
#include "mincrt/mincrt.h"
#include "nethk.h"
#include "handlers.h"

#if defined(_TRACE_NETHK)
	#define TRACE odprintfW
#else 
	#define TRACE(...)
#endif

nethk_handler *handlers_last = NULL, *handlers_first = NULL;

typedef struct _OVERLAP_DATA {
	LPWSAOVERLAPPED overlapped;
	char op;
	UINT64 magic;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine;
	LPWSATHREADID lpThreadId;
	void* pointer;
	DWORD bufcount;
	LPWSABUF buffers;
	SOCKADDR_STORAGE addrdata;
	int addrlen;
	int* p_addrlen;
	SOCKET s;
} OVERLAP_DATA;

CRITICAL_SECTION CriticalSection; 

/*
 * _handle_data: outputs nicely formatted data.
 * If OUTPUT_PIPE is defined, it sends data to the pipe as follows:
 * 
 * <op><alen><addr><data>
 * 
 * where <op> is operation code (s, r, t, f, see below), <addr> is
 * the human-readable target address as WCHAR string, <alen> is the 
 * length of <addr>, <data> is raw content
 */
enum nethk_filter _handle_data(LPOPERATION op) {
	/*if(!op->lpNumberOfBytesRecvd || !op->lpBuffers) {
		TRACE(L"_handle_data: some fields are NULL");
		return FI_ERROR;
	}*/
{		
	nethk_handler* cur = handlers_first;
	while(cur) {
		if(cur->filter) {
			enum nethk_filter result;
			if((cur->family==AF_UNSPEC || cur->family==op->lpAddr->sa_family) &&
				(cur->proto==IPPROTO_IP || cur->proto==op->proto)) {
				result = cur->filter(op);
				if(result!=FI_PASS)
					return result;
			}
		}
		cur = cur->next;
	}
	return FI_PASS;
#if 0//defined(OUTPUT_PIPE) || defined(OUTPUT_DEBUG)		
	int numberOfBytesRecvd = *op->lpNumberOfBytesRecvd, bytes_to_send = 2 + numberOfBytesRecvd, i=0, pos=2, addr_string_len=254;
	int _err;
	static WCHAR addr_string[255];
	static char* recv_data = 0;
	static int recv_data_size = 0;
	
	TRACE(L"handle_data: dwBufferCount=%d, NumberOfBytesRecvd=%d", op->dwBufferCount, numberOfBytesRecvd);		
	if(!op->lpAddr || !op->lpAddrLen) {
		addr_string_len = 2;
		addr_string[0] = L'\0';
	}
	else {
		orig_WSPAddressToString((LPSOCKADDR)op->lpAddr, *op->lpAddrLen, NULL, addr_string, &addr_string_len, &_err);
		addr_string_len*=2;
	}
#ifdef OUTPUT_PIPE
	bytes_to_send +=addr_string_len;
	pos += addr_string_len;

	//EnterCriticalSection(&CriticalSection);
	if(!recv_data)
		recv_data = mem_alloc(bytes_to_send);
	else if (bytes_to_send > recv_data_size) {
		mem_realloc(&recv_data, bytes_to_send);
		recv_data_size = bytes_to_send;
	}
	//recv_data = mem_alloc(bytes_to_send);

	recv_data[0] = op->op;
	recv_data[1] = (unsigned char)(addr_string_len/2);
	bytes_to_send -=2;

	mem_cpy(recv_data+2, addr_string, addr_string_len);
	bytes_to_send -= addr_string_len;

	for(i=0; i < op->dwBufferCount; i++) {			
		DWORD bytes_to_copy = op->lpBuffers[i].len > numberOfBytesRecvd? numberOfBytesRecvd: op->lpBuffers[i].len;
		mem_cpy(recv_data+pos, op->lpBuffers[i].buf, bytes_to_copy);					
		bytes_to_send -= bytes_to_copy;
		if(bytes_to_send < 0) {
			TRACE(L"handle_data: buffer overflow");
			break;
		}
		pos += bytes_to_copy;
	}
	_write_pipe(recv_data, pos);
	//LeaveCriticalSection(&CriticalSection);
	//mem_free(recv_data);
#else
	switch(op->op) {
	case 'r':
	case 'f':
		odprintfW(L"--- recv from %s ---", addr_string);
		break;
	case 's':
	case 't':
		odprintfW(L"--- send to %s ---", addr_string);
		break;
	}
	if(!recv_data)
		recv_data = mem_alloc(bytes_to_send);
	else if (bytes_to_send > recv_data_size) {
		mem_realloc(&recv_data, bytes_to_send);
		recv_data_size = bytes_to_send;
	}
	pos = 0; bytes_to_send = numberOfBytesRecvd;
	for(i=0; i < op->dwBufferCount; i++) {			
		DWORD bytes_to_copy = op->lpBuffers[i].len > numberOfBytesRecvd? numberOfBytesRecvd: op->lpBuffers[i].len;
		mem_cpy(recv_data+pos, op->lpBuffers[i].buf, bytes_to_copy);					
		bytes_to_send -= bytes_to_copy;
		if(bytes_to_send < 0) {
			TRACE(L"handle_data: buffer overflow");
			break;
		}
		pos += bytes_to_copy;
	}
	OutputDebugStringA(_format_data(numberOfBytesRecvd, recv_data));
	OutputDebugStringA("\n");
#endif // ifdef OUTPUT_PIPE
#endif // if defined(OUTPUT_PIPE) || defined(OUTPUT_DEBUG)		
}
}

LPWSPPROC_TABLE tbl;
HANDLE hWS32;

/*
 * see nethk.h for description
 */
BOOL nethk_install() {
	BOOL success = TRUE;
	if(!mincrt_init(1024*1024)) {
		TRACE(L"error: cannot initialize mincrt");
		return FALSE;
	}
#if defined(_TRACE) && defined(_TRACE_FILE)
	_log = fopen("c:/Temp/nethk.txt", "w");
#endif				
	InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400);
	tbl = get_sockproctable();		
	my_WSPCloseSocket = _my_WSPCloseSocket;
	my_WSPConnect = _my_WSPConnect;
	my_WSPRecvFrom = _my_WSPRecvFrom;
	my_WSPRecv = _my_WSPRecv;
	my_WSPGetOverlappedResult = _my_WSPGetOverlappedResult;
	my_WSPSend = _my_WSPSend;
	my_WSPSendTo = _my_WSPSendTo;	
	orig_WSPCancelBlockingCall = tbl->lpWSPCancelBlockingCall;
/*
	hWS32 = LoadLibraryA("ws2_32.dll");
	if(hWS32) {
		_WPUCompleteOverlappedRequest = GetProcAddress(hWS32, "WPUCompleteOverlappedRequest");			
		if(_WPUCompleteOverlappedRequest) {
			TRACE(L"Found WPUCompleteOverlappedRequest");
		}
	}	
	HOOK_IMPL_N(WPUCompleteOverlappedRequest);
*/
	Mhook_begin();	
	HOOK_INSTALL(WSPAccept, tbl);		
	HOOK_INSTALL(WSPAddressToString, tbl);
	HOOK_INSTALL(WSPAsyncSelect, tbl);
	HOOK_INSTALL(WSPBind, tbl);
	//HOOK_INSTALL(WSPCancelBlockingCall, tbl);
	HOOK_INSTALL(WSPCloseSocket, tbl);
	HOOK_INSTALL(WSPCleanup, tbl);
	HOOK_INSTALL(WSPConnect, tbl);
	HOOK_INSTALL(WSPDuplicateSocket, tbl);
	HOOK_INSTALL(WSPEnumNetworkEvents, tbl);
	HOOK_INSTALL(WSPEventSelect, tbl);
	HOOK_INSTALL(WSPGetOverlappedResult, tbl);
	HOOK_INSTALL(WSPGetPeerName, tbl);
	HOOK_INSTALL(WSPGetSockName, tbl);
	HOOK_INSTALL(WSPGetSockOpt, tbl);
	HOOK_INSTALL(WSPGetQOSByName, tbl);
	HOOK_INSTALL(WSPIoctl, tbl);
	HOOK_INSTALL(WSPJoinLeaf, tbl);
	HOOK_INSTALL(WSPListen, tbl);
	HOOK_INSTALL(WSPRecv, tbl);
	HOOK_INSTALL(WSPRecvDisconnect, tbl);
	HOOK_INSTALL(WSPRecvFrom, tbl);
	HOOK_INSTALL(WSPSelect, tbl);
	HOOK_INSTALL(WSPSend, tbl);
	HOOK_INSTALL(WSPSendDisconnect, tbl);
	HOOK_INSTALL(WSPSendTo, tbl);
	HOOK_INSTALL(WSPSetSockOpt, tbl);
	HOOK_INSTALL(WSPShutdown, tbl);
	HOOK_INSTALL(WSPSocket, tbl);
	HOOK_INSTALL(WSPStringToAddress, tbl);				
	Mhook_end();

	return success;
}

/*
 * see nethk.h for description
 */
BOOL nethk_uninstall() {
	BOOL success = TRUE;
	Mhook_begin();	
	HOOK_UNINSTALL(WSPAccept);		
	HOOK_UNINSTALL(WSPAddressToString);
	HOOK_UNINSTALL(WSPAsyncSelect);
	HOOK_UNINSTALL(WSPBind);
	//HOOK_UNINSTALL(WSPCancelBlockingCall);
	HOOK_UNINSTALL(WSPCloseSocket);
	HOOK_UNINSTALL(WSPCleanup);
	HOOK_UNINSTALL(WSPConnect);
	HOOK_UNINSTALL(WSPDuplicateSocket);
	HOOK_UNINSTALL(WSPEnumNetworkEvents);
	HOOK_UNINSTALL(WSPEventSelect);
	HOOK_UNINSTALL(WSPGetOverlappedResult);
	HOOK_UNINSTALL(WSPGetPeerName);
	HOOK_UNINSTALL(WSPGetSockName);
	HOOK_UNINSTALL(WSPGetSockOpt);
	HOOK_UNINSTALL(WSPGetQOSByName);
	HOOK_UNINSTALL(WSPIoctl);
	HOOK_UNINSTALL(WSPJoinLeaf);
	HOOK_UNINSTALL(WSPListen);
	HOOK_UNINSTALL(WSPRecv);
	HOOK_UNINSTALL(WSPRecvDisconnect);
	HOOK_UNINSTALL(WSPRecvFrom);
	HOOK_UNINSTALL(WSPSelect);
	HOOK_UNINSTALL(WSPSend);
	HOOK_UNINSTALL(WSPSendDisconnect);
	HOOK_UNINSTALL(WSPSendTo);
	HOOK_UNINSTALL(WSPSetSockOpt);
	HOOK_UNINSTALL(WSPShutdown);
	HOOK_UNINSTALL(WSPSocket);
	HOOK_UNINSTALL(WSPStringToAddress);		
	Mhook_end();	
#if defined(_TRACE) && defined(_TRACE_FILE)		
	fclose(_log);		
#endif
	return success;
}

enum nethk_error nethk_add_handler(nethk_handler* h) {			
	if(!h) return E_INVALID_ARG;
	if(handlers_last)
		handlers_last->next = h;
	handlers_last = h;
	h->next = NULL;
	if(!handlers_first) handlers_first = h;

	return E_SUCCESS;
}
enum nethk_error nethk_remove_handler(nethk_handler* h) {
	nethk_handler* cur = handlers_first;
	if(!handlers_first)
		return E_SUCCESS;	
	if(handlers_first==h) {
		handlers_first = handlers_first->next;
		return E_SUCCESS;
	}
	while(cur) {
		if(cur->next==h) {
			cur->next = cur->next->next;
			h->next = 0;
			return E_SUCCESS;
		}
		cur = cur->next;
	}
	// could not find desired pointer...
	return E_INVALID_ARG;
}
enum nethk_error nethk_get_data( const nethk_operation* op, BYTE* buf, LPDWORD len )
{	
	DWORD numberOfBytesRecvd, pos = 0, i, buflen;
	enum nethk_error result = E_SUCCESS;
	if(!op || !op->lpNumberOfBytesRecvd || !op->lpBuffers || !len)
		return E_INVALID_ARG;		
	if(!buf) {		
		*len = *op->lpNumberOfBytesRecvd;
		return E_SUCCESS;
	}

	buflen = *len;
	numberOfBytesRecvd = *op->lpNumberOfBytesRecvd;	
	for(i=0; i < op->dwBufferCount; i++) {			
		DWORD bytes_to_copy = op->lpBuffers[i].len > numberOfBytesRecvd? numberOfBytesRecvd: op->lpBuffers[i].len;
		if(bytes_to_copy > buflen) {
			bytes_to_copy = buflen;			// data will be truncated
			result = E_DATA_TRUNCATED;
		}
		mem_cpy(buf+pos, op->lpBuffers[i].buf, bytes_to_copy);							
		pos += bytes_to_copy;
		buflen -= bytes_to_copy;
		if(!buflen) break;
	}
	*len = pos;
	return result;
}
enum nethk_error nethk_set_data(nethk_operation* op, BYTE* buf, DWORD buflen) {
	DWORD buf_i, pos = 0, _buflen = buflen, copied = 0;
	enum nethk_error res = E_SUCCESS;
	if(!op->dwBufferCount || !op->lpBuffers)
		return E_INVALID_ARG;
	for(buf_i = 0; buf_i < op->dwBufferCount; buf_i++) {
		WSABUF lpbuf = op->lpBuffers[buf_i];
		mem_cpy(lpbuf.buf, buf+pos, lpbuf.len > buflen? buflen: lpbuf.len);
		copied += lpbuf.len > buflen? buflen: lpbuf.len;

		if(lpbuf.len > buflen) {
			pos += buflen;
			buflen -= lpbuf.len;
		}
		else if(buflen) {
			buflen = 0;
			op->dwBufferCount = buf_i+1;
			break;
		}
	}
	if(copied < _buflen) {
		res = E_DATA_TRUNCATED;
	}
	/*op->numberOfBytesRecvd = _buflen;
	op->lpNumberOfBytesRecvd = &op->lpNumberOfBytesRecvd;*/
	*(op->lpNumberOfBytesRecvd) = copied;
	return res;
}

enum nethk_operation_type nethk_get_operation(const nethk_operation* op) {
	switch(op->op) {
	case 'r':
	case 'f':
		return OP_RECV;
	case 's':
	case 't':
		return OP_SEND;
	case 'a':
		return OP_ACCEPT;
	case 'c':
		return OP_CONNECT;
	case 'd':
		return OP_DISCONNECT;
	default:
		return OP_UNKNOWN;
	};
};

enum nethk_error nethk_get_address_string( const nethk_operation* op, WCHAR* addr, LPDWORD addrlen )
{
	int _err, _res;
	if(!addr || !addrlen)
		return E_INVALID_ARG;
	if(!op->lpAddr || !op->lpAddrLen) {
		*addrlen = 2;
		addr[0] = L'\0';
	}
	else {
		_res = orig_WSPAddressToString((LPSOCKADDR)op->lpAddr, *op->lpAddrLen, NULL, addr, addrlen, &_err);
		if(_res==SOCKET_ERROR) {
			if(_err==WSAEFAULT) 
				return E_DATA_TRUNCATED;
			else if(_err==WSAEINVAL)
				return E_INVALID_ARG;
		}		
	}
	return E_SUCCESS;
};

void _error_message(LPWSTR lpszFunction) 
{ 
	// Retrieve the system error message for the last-error code
	static WCHAR lpMsgBuf[1024];
	static WCHAR lpDisplayBuf[1024];
	DWORD dw = GetLastError(); 
	HMODULE m = LoadLibrary(L"wininet.dll");

	FormatMessage(
		//FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_HMODULE,
		m,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		lpMsgBuf,
		1024, NULL );

	wsprintfW(lpDisplayBuf, L"%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf); 
	TRACE(lpDisplayBuf);
}
