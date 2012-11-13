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

#if defined(_TRACE_HANDLERS)
#define TRACE odprintfW
#else 
#define TRACE(...)
#endif

void* current_hook;
extern CRITICAL_SECTION CriticalSection;

#define _HOOK_IMPLEMENT
#define HOOK_IMPL(fRET, fNAME, fARGS, fARGNAMES) \
	pointer_to_##fNAME fNAME, orig_##fNAME, my_##fNAME; \
	fRET WSPAPI fNAME##_handler fARGS { \
		fRET ret; \
		/*EnterCriticalSection(&CriticalSection); */current_hook = orig_##fNAME; /*LeaveCriticalSection(&CriticalSection); */ \
		TRACE(L"Entered %hs_handler", #fNAME); \
		if(my_##fNAME) { \
			TRACE(L"Entered _my_%hs", #fNAME); \
			ret = my_##fNAME fARGNAMES; \
			TRACE(L"Exited _my_%hs", #fNAME); \
		} else { \
			TRACE(L"calling %hs", #fNAME); \
			ret = orig_##fNAME fARGNAMES; \
		} \
		current_hook = NULL; \
		TRACE(L"Exited %hs_handler", #fNAME); return ret; \
	}
#include "handlers.h"

extern enum nethk_filter _handle_data(LPOPERATION op);	// defined in nethk.c
extern void _error_message(LPWSTR);

void _handle_overlapped(LPOPERATION* _op) {	
	INT _res, _err, _optlen;
	LPOPERATION op;
	WSAPROTOCOL_INFOW protocol_info;

	//TODO: EnterCriticalSection(&CriticalSection);

	_optlen = sizeof(protocol_info);
	if((*_op)->lpOverlapped) {
		op = mem_alloc(sizeof(nethk_operation));		
		*op = **_op;

		op->lpOverlapped_Pointer = op->lpOverlapped->Pointer;
		op->lpOverlapped->Pointer = op;
		TRACE(L"Overlapped %hc operation %p", op->op, op->lpOverlapped);									

		//*_op = op;
	} else if((*_op)->lpCompletionRoutine) {
		TRACE(L"Overlapped operation: completion routine without lpOverlapped"); 

		op = *_op;
	} else {
		op = *_op;
	}	

	if(!op->lpAddr) {			
		op->addrLen = sizeof(SOCKADDR_STORAGE);
		op->lpAddrLen = &op->addrLen;
		op->lpAddr = &op->addr;
		_res = orig_WSPGetPeerName(op->s, op->lpAddr, op->lpAddrLen, &_err);
		if(_res) {
			//TRACE(L"recv: cannot get peer name");
			SetLastError(_err);
			_error_message(L"WSPGetPeerName");
		}
	}

	_res = orig_WSPGetSockOpt(op->s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&protocol_info, &_optlen ,&_err);
	if(_res) {
		SetLastError(_err);
		_error_message(L"WSPGetSockOpt");
		op->proto = IPPROTO_IP;
	} else op->proto = protocol_info.iProtocol;

	//TODO: LeaveCriticalSection(&CriticalSection);
}


enum nethk_filter _handle_operation(LPOPERATION op) {	
	enum nethk_filter res = FI_PASS;
	
	//TODO: EnterCriticalSection(&CriticalSection);

	if(op) {
		TRACE(L"handle_operation %hc on socket %08x", op->op, op->s);
		if(op->res == 0) {																// synchronous operation
			return _handle_data(op);
		} else if(op->res==SOCKET_ERROR && op->lpErrno && *op->lpErrno==WSA_IO_PENDING) {	// overlapped operation
			if(!op->lpOverlapped && !op->lpCompletionRoutine)
				TRACE(L"Overlapped operation???");
			else TRACE(L"overlapped operation");			
		} else if(op->lpErrno) {															// no operation - error returned
			if(op->op=='c' && *op->lpErrno==WSAEWOULDBLOCK)
				return _handle_data(op);
			SetLastError(*op->lpErrno);
			_error_message(L"operation");
		} else {																			// same, in case if lpErrno==NULL
			TRACE(L"operation %hc returned %d", op->op, op->res);
		}
	}

	//TODO: LeaveCriticalSection(&CriticalSection);

	return res;
}


/*
 * The functions _my_WSP* defined below are hooks for WinAPI WSP* functions.
 * The *Send* and *Recv* hooks work similar to each other. If the operation
 * is not overlapped (this is detected by the precense of WSAOVERLAPPED 
 * argument) the data stored in LPWSABUF (array of WSABUF buffers) is the 
 * data we need to intercept. Currently it is just formatted for nice output 
 * and written to debug output or named pipe (depending on OUTPUT_PIPE macro).
 * Otherwise a new OVERLAP_DATA object is created which stores pointers to
 * data buffers, target address and operation code (s, r, t, f for Send, Recv,
 * SendTo and RecvFrom). The WSAOVERLAPPED  object passed to _my_WSP* function 
 * by the target program is modified in a way that will not have any impact on
 * the program: its 'Pointer' field is pointed to the OVERLAP_DATA object described
 * above. When the target program calls WSPGetOverlappedResult or any other
 * overlapped functions the modified WSAOVERLAP object will contain a pointer
 * to OVERLAP_DATA with all the info on the operation requested.
 */

BOOL WSPAPI _my_WSPGetOverlappedResult (SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags, LPINT lpErrno) {
	int res;
	LPOPERATION o = lpOverlapped->Pointer; 
	if(!o) {		// the lpOverlapped was not modified by any of _my_WSP*
		TRACE(L"overlaped operation was not intercepted");
		return orig_WSPGetOverlappedResult(s,lpOverlapped,lpcbTransfer,fWait,lpdwFlags,lpErrno);
	}
	else {			// otherwise, let's hope that we have a valid nethk_operation pointer :)
		lpOverlapped->Pointer = o->lpOverlapped_Pointer;
		res = orig_WSPGetOverlappedResult(s,o->lpOverlapped,lpcbTransfer,fWait,lpdwFlags,lpErrno);
		TRACE(L"getting overlapped \'%hc\' result intercepted (%s)!", o->op, res==TRUE? L"ok": L"error");
		if(res == TRUE) {
			o->lpNumberOfBytesRecvd = lpcbTransfer;
			_handle_data(o);
			mem_free(o);
		}
		else if(res == FALSE && *lpErrno == WSA_IO_PENDING) {
			mem_free(o);
		}
	}
	return res;
}

int WSPAPI _my_WSPSend (
		SOCKET s, 
		LPWSABUF lpBuffers, 
		DWORD dwBufferCount,	
		LPDWORD lpNumberOfBytesRecvd, 
		DWORD flags,	
		LPWSAOVERLAPPED lpOverlapped,	
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
		LPWSATHREADID lpThreadId, 
		LPINT lpErrno ) {
	nethk_operation _op = {0}, *op = &_op;
	op->op = 's';
	op->s = s;
	op->lpBuffers = lpBuffers;
	op->dwBufferCount = dwBufferCount;
	op->lpNumberOfBytesRecvd = lpNumberOfBytesRecvd;	
	op->lpAddrLen = &op->addrLen;
	op->lpOverlapped = lpOverlapped;
	;
	op->lpCompletionRoutine = lpCompletionRoutine;
	op->lpErrno = lpErrno;

	_handle_overlapped(&op);
	op->res = orig_WSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, flags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	_handle_operation(op);
	return op->res;
}

int WSPAPI _my_WSPSendTo (
		SOCKET s, 
		LPWSABUF lpBuffers, 
		DWORD dwBufferCount,	
		LPDWORD lpNumberOfBytesRecvd, 
		DWORD dwFlags,	
		const struct sockaddr *lpFrom, 
		int iTolen,	
		LPWSAOVERLAPPED lpOverlapped,	
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
		LPWSATHREADID lpThreadId, 
		LPINT lpErrno ) {	
	nethk_operation _op = {0}, *op = &_op;
	op->op = 't';
	op->s = s;
	op->lpBuffers = lpBuffers;
	op->dwBufferCount = dwBufferCount;
	op->lpNumberOfBytesRecvd = lpNumberOfBytesRecvd;
	op->lpAddr = lpFrom;
	op->addrLen = iTolen;
	op->lpAddrLen = &op->addrLen;
	op->lpOverlapped = lpOverlapped;
	;
	op->lpCompletionRoutine = lpCompletionRoutine;
	op->lpErrno = lpErrno;

	_handle_overlapped(&op);
	op->res = orig_WSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, dwFlags, lpFrom, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	_handle_operation(op);
	return op->res;
}

int WSPAPI _my_WSPRecvFrom	(
		SOCKET s, 
		LPWSABUF lpBuffers, 
		DWORD dwBufferCount,	
		LPDWORD lpNumberOfBytesRecvd, 
		LPDWORD lpFlags, 
		struct sockaddr *lpFrom,	
		LPINT lpFromlen, 
		LPWSAOVERLAPPED lpOverlapped,	
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
		LPWSATHREADID lpThreadId, 
		LPINT lpErrno	) {	
	nethk_operation _op = {0}, *op = &_op;
	op->op = 'f';
	op->s = s;
	op->lpBuffers = lpBuffers;
	op->dwBufferCount = dwBufferCount;
	op->lpNumberOfBytesRecvd = lpNumberOfBytesRecvd;
	op->lpAddr = lpFrom;	
	op->lpAddrLen = lpFromlen;
	op->lpOverlapped = lpOverlapped;
	;
	op->lpCompletionRoutine = lpCompletionRoutine;
	op->lpErrno = lpErrno;

	_handle_overlapped(&op);
	op->res = orig_WSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);	
	_handle_operation(op);
	return op->res;
}

int WSPAPI _my_WSPRecv	(
		SOCKET s, 
		LPWSABUF lpBuffers, 
		DWORD dwBufferCount,	
		LPDWORD lpNumberOfBytesRecvd, 
		LPDWORD lpFlags, 
		LPWSAOVERLAPPED lpOverlapped,	
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
		LPWSATHREADID lpThreadId, 
		LPINT lpErrno	) {	
	nethk_operation _op = {0}, *op = &_op;
	op->op = 'r';
	op->s = s;
	op->lpBuffers = lpBuffers;
	op->dwBufferCount = dwBufferCount;
	op->lpNumberOfBytesRecvd = lpNumberOfBytesRecvd;	
	op->lpOverlapped = lpOverlapped;
	;
	op->lpCompletionRoutine = lpCompletionRoutine;
	op->lpErrno = lpErrno;

	_handle_overlapped(&op);
	op->res = orig_WSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	_handle_operation(op);
	return op->res;
}

int WSPAPI _my_WSPConnect		(
		SOCKET s, 
		const struct sockaddr *name, 
		int namelen, 
		LPWSABUF lpCallerData, 
		LPWSABUF lpCalleeData, 
		LPQOS lpSQOS, 
		LPQOS lpGQOS, 
		LPINT lpErrno	) {
	nethk_operation _op = {0}, *op = &_op;
	op->op = 'c';
	op->s = s;
	op->lpErrno = lpErrno;
	op->lpAddr = name;
	op->addrLen = namelen;
	op->lpAddrLen = &op->addrLen;

	_handle_overlapped(&op);
	op->res = orig_WSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
	_handle_operation(op);
	return op->res;
}

int WSPAPI _my_WSPCloseSocket	(
		SOCKET s, 
		LPINT lpErrno		) {
	nethk_operation _op = {0}, *op = &_op;
	op->op = 'd';
	op->s = s;
	op->lpErrno = lpErrno;

	_handle_overlapped(&op);
	op->res = orig_WSPCloseSocket(s, lpErrno);
	_handle_operation(op);
	return op->res;
}
