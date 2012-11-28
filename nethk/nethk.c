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
#include "cbuf.h"

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

CRITICAL_SECTION csFilter, csWait; 

/*
 * _handle_data: 
 *	Calls user-defined handlers in the order they were added. If a handler
 *	returns a result other than FI_PASS, no other handlers will be called.
 *	Otherwise, a next added handler will be called.
 * Returns: 
 *	FI_PASS if all handlers returned FI_PASS; otherwise, the return value
 *	of the handler which returned non-FI_PASS.
 */

enum nethk_filter _handle_data(LPOPERATION op) {	
	nethk_handler* cur = handlers_first;
	while(cur) {
		if(cur->filter) {
			enum nethk_filter result;
			if((cur->family==AF_UNSPEC || cur->family==op->lpAddr->sa_family) &&
				(cur->proto==IPPROTO_IP || cur->proto==op->proto)) {
				EnterCriticalSection(&csFilter);
					result = cur->filter(op);
				LeaveCriticalSection(&csFilter);
				if(result!=FI_PASS)
					return result;
			}
		}
		cur = cur->next;
	}
	return FI_PASS;	
}

typedef DWORD (WINAPI * lpWaitForSingleObject) (
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds
	);
lpWaitForSingleObject orig_WaitForSingleObject = WaitForSingleObject;
DWORD WINAPI _my_WaitForSingleObject(
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds
	) {
		return orig_WaitForSingleObject(hHandle, dwMilliseconds);
}

LPWSPPROC_TABLE tbl;
HANDLE hWS32;
#define NETHK_OPERATIONS_N 1024
nethk_sockbuf operations[NETHK_OPERATIONS_N];

/*
 * see nethk.h for description
 */
BOOL nethk_install() {
	BOOL success = TRUE;
	DWORD i;
	for(i=0; i<NETHK_OPERATIONS_N; i++) {
		operations[i].s = INVALID_SOCKET;
		operations[i].userdata = NULL;
		operations[i].rb_in = NULL;
		operations[i].rb_out = NULL;
	}
	if(!mincrt_init(1024*1024)) {
		TRACE(L"error: cannot initialize mincrt");
		return FALSE;
	}
#if defined(_TRACE) && defined(_TRACE_FILE)
	_log = fopen("c:/Temp/nethk.txt", "w");
#endif				
	InitializeCriticalSectionAndSpinCount(&csFilter, 0x00000400);
	InitializeCriticalSection(&csWait);
	tbl = get_sockproctable();		
	my_WSPCloseSocket = _my_WSPCloseSocket;
	my_WSPConnect = _my_WSPConnect;
	my_WSPRecvFrom = _my_WSPRecvFrom;
	my_WSPRecv = _my_WSPRecv;
	my_WSPGetOverlappedResult = _my_WSPGetOverlappedResult;
	my_WSPSend = _my_WSPSend;
	my_WSPSendTo = _my_WSPSendTo;	
	orig_WSPCancelBlockingCall = tbl->lpWSPCancelBlockingCall;

	Mhook_begin();	
	success = Mhook_hook(&orig_WaitForSingleObjectEx, _my_WaitForSingleObjectEx);
	HOOK_INSTALL(WSPAccept, tbl);		
	HOOK_INSTALL(WSPAddressToString, tbl);
	HOOK_INSTALL(WSPAsyncSelect, tbl);
	HOOK_INSTALL(WSPBind, tbl);
	
	// This function doen't need to be intercepted. Instead, it is used in Mhook_unhook
	// to stop any blocking operations.
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
	Mhook_unhook(&orig_WaitForSingleObjectEx);
	HOOK_UNINSTALL(WSPAccept);		
	HOOK_UNINSTALL(WSPAddressToString);
	HOOK_UNINSTALL(WSPAsyncSelect);
	HOOK_UNINSTALL(WSPBind);

	// See nethk_install above for explanation
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
	mincrt_deinit();
#if defined(_TRACE) && defined(_TRACE_FILE)		
	fclose(_log);		
#endif
	return success;
}

enum nethk_error nethk_add_handler(nethk_handler* h) {			
	if(!h) return E_INVALID_ARG;
	EnterCriticalSection(&csFilter);
		if(handlers_last)
			handlers_last->next = h;
		handlers_last = h;
		h->next = NULL;
		if(!handlers_first) handlers_first = h;
	LeaveCriticalSection(&csFilter);
	return E_SUCCESS;
}
enum nethk_error nethk_remove_handler(nethk_handler* h) {
	nethk_handler* cur = handlers_first;
	enum nethk_error _err = E_INVALID_ARG;
	EnterCriticalSection(&csFilter);
		if(handlers_first) {	
			if(handlers_first==h) {
				handlers_first = handlers_first->next;			
				_err = E_SUCCESS;
			} else 
			  while(cur) {
				if(cur->next==h) {
					cur->next = cur->next->next;
					h->next = 0;
					_err = E_SUCCESS;
					break;
				}
				cur = cur->next;
			}
		}
		// could not find desired pointer: return E_INVALID_ARG
	LeaveCriticalSection(&csFilter);
	return _err;
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
enum nethk_error nethk_set_data(nethk_operation* op, BYTE* buf, LPDWORD lpBuflen) {
	DWORD buf_i, pos = 0, buflen = *lpBuflen, _buflen = buflen, copied = 0;
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
	*lpBuflen = copied;
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

nethk_sockbuf* _get_sockbuf(SOCKET s) {
	int i, first_zero = -1;
	DWORD n, _err, _optlen = sizeof(BOOL);
	static clib_map* sockbuf_map = NULL;
	if(!sockbuf_map)

	if(orig_WSPGetSockOpt(s, SOL_SOCKET, SO_DEBUG, &n, &_optlen, &_err)) {
		TRACE(L"Cannot get SO_DEBUG");
		SetLastError(_err);
		_error_message(L"WSPGetSockOpt");
	} else if(n == 0 || n > NETHK_OPERATIONS_N) {
		for(i=0; i<NETHK_OPERATIONS_N; i++) { 
			if(first_zero==-1 && operations[i].s==INVALID_SOCKET) {
				first_zero = i;
			} else if(operations[i].s == s) {
				n = i+1;
				//orig_WSPSetSockOpt(s, SOL_SOCKET, SO_DEBUG, &n, sizeof(BOOL), &_err);
				return operations + i;
			}
		}
		if(first_zero!=-1) {		
			operations[first_zero].s = s;
			n = first_zero +1;
			//orig_WSPSetSockOpt(s, SOL_SOCKET, SO_DEBUG, &n, sizeof(BOOL), &_err);
			return operations + first_zero;
		} else {
			TRACE(L"No more sockbuf object available! Going to crash!");
		}
	} else {
		return operations + n-1;
	}
	return NULL;	// this would be baaad
}