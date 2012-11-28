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
#include "cbuf.h"
#include "c_lib.h"
#include "c_map.h"

#if defined(_TRACE_HANDLERS)
#define TRACE odprintfW
#define FAIL(f) _error_message(L#f)
#else 
#define TRACE(...)
#define FAIL(f)
#endif

void* current_hook;

#define _HOOK_IMPLEMENT
#define HOOK_IMPL(fRET, fNAME, fARGS, fARGNAMES) \
	pointer_to_##fNAME fNAME, orig_##fNAME, my_##fNAME; \
	fRET WSPAPI fNAME##_handler fARGS { \
		fRET ret; \
		/*EnterCriticalSection(&CriticalSection); */current_hook = orig_##fNAME; /* LeaveCriticalSection(&CriticalSection); */ \
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

#define  NOT_A_SYSTEM_CALL 0x10000000
extern CRITICAL_SECTION csWait;

struct clib_map* event_map = NULL;
int _compare_handles(void* v1, void* v2) {
	HANDLE h1 = *(LPHANDLE)v1, h2 = *(LPHANDLE)v2;
	return h1 < h2? -1 : (h1 > h2? 1: (0));
}

extern enum nethk_filter _handle_data(LPOPERATION op);	// defined in nethk.c

/*
 * _handle_overlapped: 
 *	Initializes nethk_operation object for intercepting overlapped data.
 * Returns: 
 *	A nethk_sockbuf object if possible; NULL otherwise.
 */

void _handle_overlapped(LPOPERATION* _op) {	
	INT _res, _err, _optlen;
	LPOPERATION op;
	WSAPROTOCOL_INFOW protocol_info;
	// EnterCriticalSection(&CriticalSection);
	_optlen = sizeof(protocol_info);
	if((*_op)->lpOverlapped) {
		op = mem_zalloc(sizeof(nethk_operation));		
		*op = **_op;

		op->lpOverlapped_Pointer = op->lpOverlapped->Pointer;
		op->lpOverlapped->Pointer = op;
		TRACE(L"Overlapped %hc operation %p", op->op, op->lpOverlapped);					
#if 0	// Experimental. Should be functional in the next version
		if(op->lpOverlapped->hEvent) {
			EnterCriticalSection(&csWait)
				clib_error e;
								
				if(!event_map) {
					event_map = new_c_map(_compare_handles, NULL, NULL);
				}
				e = insert_c_map(event_map, &op->lpOverlapped->hEvent, sizeof(HANDLE), op, sizeof(nethk_operation));
				if(e == CLIB_RBTREE_KEY_DUPLICATE) {
					remove_c_map(event_map, &op->lpOverlapped->hEvent);
					insert_c_map(event_map, &op->lpOverlapped->hEvent, sizeof(HANDLE), op, sizeof(nethk_operation));
				}
			LeaveCriticalSection(&csWait);			
		}
#endif
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
		op->lpAddr = (struct sockaddr*)&op->addr;
		_res = orig_WSPGetPeerName(op->s, op->lpAddr, op->lpAddrLen, &_err);
		if(_res) {			
			SetLastError(_err);
			FAIL(WSPGetPeerName);
		}
	}

	_res = orig_WSPGetSockOpt(	op->s, 
								SOL_SOCKET,
								SO_PROTOCOL_INFOW, 
								(char*)&protocol_info, 
								&_optlen ,
								&_err);
	if(_res) {
		SetLastError(_err);
		FAIL(WSPGetSockOpt);
		op->proto = IPPROTO_IP;
	} else op->proto = protocol_info.iProtocol;
	// LeaveCriticalSection(&CriticalSection);
}

/*
 * _handle_operation: 
 *	Decides whether to pass intercepted data to filters. The decision is based on
 *	the WSP* function's return code, error code and the state of overlapped operation.
 * Returns: 
 *	FI_PASS or FI_QUEUE, depending on the result of _handle_data();
 *	FI_ERROR if WSP* function reported an error.
 */

enum nethk_filter _handle_operation(LPOPERATION op) {	
	enum nethk_filter res = FI_PASS;	
	// EnterCriticalSection(&CriticalSection);
	if(op) {
		TRACE(L"handle_operation %hc on socket %08x", op->op, op->s);
		if(op->res == 0) {																// synchronous operation
			res = _handle_data(op);
		} else if(op->res==SOCKET_ERROR && op->lpErrno && *op->lpErrno==WSA_IO_PENDING) {	// overlapped operation
			if(!op->lpOverlapped && !op->lpCompletionRoutine)
				TRACE(L"Overlapped operation???");
			else TRACE(L"overlapped operation");			
		} else if(op->lpErrno) {															// no operation - error returned
			if(op->op=='c' && *op->lpErrno==WSAEWOULDBLOCK)
				res = _handle_data(op);
			else {
				SetLastError(*op->lpErrno);
				FAIL(operation);
				res = FI_ERROR;
			}
		} else {																			// same, in case if lpErrno==NULL
			TRACE(L"operation %hc returned %d", op->op, op->res);
			if(op->res==0)
				res = FI_ERROR;
		}
	}
	// LeaveCriticalSection(&CriticalSection);
	return res;
}

lpWaitForSingleObjectEx orig_WaitForSingleObjectEx = WaitForSingleObjectEx;

DWORD WINAPI _my_WaitForSingleObjectEx(
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds,
	_In_ BOOL bAlertable
	) {		
#if 0	// Experimental. Should be functional in the next version
		DWORD res;
		//if(!TryEnterCriticalSection(&csWait))
			//return WAIT_TIMEOUT;		
		EnterCriticalSection(&csWait);
		
		if(hHandle == NULL)
			return WAIT_OBJECT_0;

		if(event_map && exists_c_map(event_map, &hHandle)) {
			LPOPERATION op;
			static DWORD dwFlags = NOT_A_SYSTEM_CALL, dwErr;				
			//EnterCriticalSection(&csWait);			
			dwFlags = NOT_A_SYSTEM_CALL;
			find_c_map(event_map, &hHandle, &op);			
				if(_my_WSPGetOverlappedResult(op->s, op->lpOverlapped, op->lpNumberOfBytesRecvd, FALSE, &dwFlags, &dwErr))
					res = WAIT_OBJECT_0;
				else res = WAIT_TIMEOUT;
			//}
			//_my_WSPGetOverlappedResult()			
			LeaveCriticalSection(&csWait);
			TRACE(L"Wait (sim) for event %p: %d", hHandle, res);
		}
		else {
			LeaveCriticalSection(&csWait);
			res = orig_WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);		
			TRACE(L"Wait for event %p: %d", hHandle, res);
		}		
		return res;
#else 
		DWORD res = orig_WaitForSingleObjectEx(hHandle, dwMilliseconds, bAlertable);						
		return res;
#endif
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
	nethk_sockbuf* sockbuf = _get_sockbuf(s);

	if(!o) {		// the lpOverlapped was not modified by any of _my_WSP*
		TRACE(L"overlaped operation was not intercepted");
		return orig_WSPGetOverlappedResult(s,lpOverlapped,lpcbTransfer,fWait,lpdwFlags,lpErrno);
	}
	else {			// otherwise, let's hope that we have a valid nethk_operation pointer :)
		lpOverlapped->Pointer = o->lpOverlapped_Pointer;
		res = orig_WSPGetOverlappedResult(s,o->lpOverlapped,lpcbTransfer,fWait,lpdwFlags,lpErrno);
		TRACE(L"getting overlapped \'%hc\' result intercepted (%s)!", o->op, res==TRUE? L"ok": L"error");
		if(res == TRUE) {
			enum nethk_filter fi;
			o->lpNumberOfBytesRecvd = lpcbTransfer;
			fi = _handle_data(o);
			switch(fi) {
			case FI_PASS:				
				break;
			case FI_QUEUE:
				// not supported yet
				if(!o->dwBytesToRecv) {
					ring_buffer_free(sockbuf->rb_out);
					sockbuf->rb_out = NULL;
				}
				break;
			case FI_DROP:
				*lpcbTransfer = 0;
				break;
			}
			mem_free(o);
		}
		else if(res == FALSE && *lpErrno == WSA_IO_PENDING) {
			mem_free(o);
		}
	}
	return res;
}
#if 0	// Experimental. Should be functional in the next version
BOOL WSPAPI _my_WSPGetOverlappedResult ( SOCKET s, 
										LPWSAOVERLAPPED lpOverlapped, 
										LPDWORD lpcbTransfer, 
										BOOL fWait, 
										LPDWORD lpdwFlags, 
										LPINT lpErrno) {
	int _res, _err;
	LPOPERATION o = lpOverlapped->Pointer; 
	nethk_sockbuf* sockbuf = _get_sockbuf(s);
	DWORD _data_written;
	BOOL not_a_system_call = (*lpdwFlags & NOT_A_SYSTEM_CALL);

	if(!o) {		// the lpOverlapped was not modified by any of _my_WSP*
		TRACE(L"overlaped operation was not intercepted");
		if(not_a_system_call) {
			// impossible?
			TRACE(L"_my_WSPGetOverlappedResult: not a system call and LPOPERATION is NULL");
			DebugBreak();
			return FALSE;	
		}
		return orig_WSPGetOverlappedResult(s,lpOverlapped,lpcbTransfer,fWait,lpdwFlags,lpErrno);
	}
	else {			// otherwise, let's hope that we have a valid nethk_operation pointer :)	
		o->lpNumberOfBytesRecvd = lpcbTransfer;

		if(sockbuf->rb_out && ring_buffer_count_bytes(sockbuf->rb_out)) {
			
			if(not_a_system_call)
				return TRUE;

			_data_written = ring_buffer_count_bytes(sockbuf->rb_out);
			_err = nethk_set_data ( o, 
									ring_buffer_read_address(sockbuf->rb_out), 
									&_data_written );
			ring_buffer_read_advance( sockbuf->rb_out, _data_written );
			o->res = 0;
			TRACE(L"my_WSPGetOverlappedResult: dequeue old %d bytes", _data_written);
		} else {
			lpOverlapped->Pointer = o->lpOverlapped_Pointer;
			o->res = orig_WSPGetOverlappedResult ( s,
												o->lpOverlapped,
												lpcbTransfer,
												fWait,
												lpdwFlags,
												lpErrno );
			lpOverlapped->Pointer = o;
			TRACE(L"getting overlapped \'%hc\' result intercepted (%s)!", 
					o->op, 
					o->res==TRUE? L"ok": L"error");

			if(o->res == TRUE) {
				enum nethk_filter fi;
				o->lpNumberOfBytesRecvd = lpcbTransfer;
				fi = _handle_data(o);
				switch(fi) {
				case FI_PASS: {
					if(not_a_system_call)
						return TRUE;
					if(sockbuf->rb_out && ring_buffer_count_bytes(sockbuf->rb_out)) {
						if(ring_buffer_count_free_bytes(sockbuf->rb_out) >= 
							*lpcbTransfer) {				  
							// Queue  the data received
							nethk_get_data(o, 
								ring_buffer_write_address(sockbuf->rb_out), 
								lpcbTransfer);
							ring_buffer_write_advance(sockbuf->rb_out, *lpcbTransfer);
							TRACE(L"my_WSPGetOverlappedResult: queue %d bytes", 
								*lpcbTransfer);
						} else {
							TRACE(L"Not enough space to store recvd data!");
							DebugBreak();
						}				  				  
					}
					mem_free(o);
				} break;
				case FI_QUEUE: {
					if(o->dwBytesToRecv) {
						*lpcbTransfer = 0;
						o->res = FALSE;
						*lpErrno = WSA_IO_INCOMPLETE;
						// We want WSPGetOverlappedResult to be called again
						if(nethk_get_operation(o) == OP_RECV) {
							DWORD *_lpdwFlags = lpdwFlags;
							if(not_a_system_call) {
								*lpdwFlags = 0;
							}
							lpOverlapped->Pointer = o->lpOverlapped_Pointer;
							/*_res = orig_WSPRecv (	s, 
													o->lpBuffers, 
													o->dwBufferCount, 
													o->lpNumberOfBytesRecvd,
													lpdwFlags,
													lpOverlapped,
													NULL,
													o->lpThreadId,
													lpErrno);*/
							lpOverlapped->Pointer = o;
						}
					} else {
						if(not_a_system_call)
							return TRUE;
						// The filter has processed all the data and put it into sockbuf->rb_out.
						// We give it to an application.
						_data_written = ring_buffer_count_bytes(sockbuf->rb_out);
						_err = nethk_set_data	(
							o, 
							ring_buffer_read_address(sockbuf->rb_out), &_data_written );
						ring_buffer_read_advance( sockbuf->rb_out, _data_written );
						mem_free(o);
					}
				} break;
				case FI_DROP:
					*lpcbTransfer = 0;
					o->res = FALSE;
					break;
				}
//				mem_free(o);
			}
			else if(o->res == FALSE && *lpErrno == WSA_IO_PENDING) {
//				mem_free(o);
			}
		}
	}
	return o->res;
}
#endif

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
	op->lpThreadId = lpThreadId;
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
	op->lpAddr = (struct sockaddr*)lpFrom;
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
	enum nethk_filter filter_result;
	nethk_operation _op = {0}, *op = &_op;
	nethk_sockbuf* sockbuf = _get_sockbuf(s);
	enum nethk_error _err;
	DWORD _data_written = 0;
	
	if(*lpFlags) {
		TRACE(L"WSPRecv flags: %x", *lpFlags);
		//DebugBreak();
	}

	op->op = 'r';
	op->s = s;
	op->lpBuffers = lpBuffers;
	op->dwBufferCount = dwBufferCount;
	op->lpNumberOfBytesRecvd = lpNumberOfBytesRecvd;	
	op->lpOverlapped = lpOverlapped;
	op->lpThreadId = lpThreadId;
	op->lpCompletionRoutine = lpCompletionRoutine;
	op->lpErrno = lpErrno;
	_handle_overlapped(&op);
	while(TRUE) {	
	if(sockbuf->rb_out && ring_buffer_count_bytes(sockbuf->rb_out)) {
		_data_written = ring_buffer_count_bytes(sockbuf->rb_out);
		_err = nethk_set_data	(
			op, 
			ring_buffer_read_address(sockbuf->rb_out), &_data_written );
		ring_buffer_read_advance( sockbuf->rb_out, _data_written );
		op->res = 0;
		TRACE(L"my_WSPRecv: dequeue old %d bytes", _data_written);
	} else {
		op->res = orig_WSPRecv (
					s, 
					lpBuffers, 
					dwBufferCount, 
					lpNumberOfBytesRecvd, 
					lpFlags, 
					lpOverlapped, 
					lpCompletionRoutine, 
					lpThreadId, 
					lpErrno );
		if(op->res == WSAEWOULDBLOCK)
			// This is a non-blocking socket. We have to wait until the next
			// WSPRecv call from an application.
			return op->res;
		filter_result = _handle_operation(op);
		switch(filter_result) {
		  case FI_PASS:		{	
		  
			  // The filter allowed the data to be passed to an application. There might be
			  // some queued data from the previous filter calls (see FI_QUEUE below), and
			  // this data should be stored in sockbuf->rb_out ring buffer. If so, we queue 
			  // the data we just received into the same rb_out buffer.
			  if(sockbuf->rb_out && ring_buffer_count_bytes(sockbuf->rb_out)) {
				  if(ring_buffer_count_free_bytes(sockbuf->rb_out) >= *lpNumberOfBytesRecvd) {				  
					  // Queue  the data received
					  nethk_get_data(op, 
									ring_buffer_write_address(sockbuf->rb_out), 
									lpNumberOfBytesRecvd);
					  ring_buffer_write_advance(sockbuf->rb_out, *lpNumberOfBytesRecvd);
					  TRACE(L"my_WSPRecv: queue %d bytes", *lpNumberOfBytesRecvd);
				  } else {
					  TRACE(L"Not enough space to store recvd data!");
					  DebugBreak();
				  }				  				  
				} // Otherwise, we just pass the received data to an application.
		  break;	

		} case FI_QUEUE:	{
		
			if(op->dwBytesToRecv) {
				// The filter wants the data to be queued and more data to be received. The 
				// [approximate] number of bytes to be received should be specified by the
				// filter in op->dwBytesToRecv. 						
				continue;
			} else {
				// The filter has processed all the data and put it into sockbuf->rb_out.
				// We give it to an application.
				_data_written = ring_buffer_count_bytes(sockbuf->rb_out);
				_err = nethk_set_data	(
					op, 
					ring_buffer_read_address(sockbuf->rb_out), &_data_written );
				ring_buffer_read_advance( sockbuf->rb_out, _data_written );
			}
		  break;

		} case FI_DROP:		{		
			*lpNumberOfBytesRecvd = 0;
			break;
		}}
	}
	return op->res;
	}
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
	op->lpAddr = (struct sockaddr*)name;
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
	nethk_sockbuf* sockbuf = _get_sockbuf(s);
	DWORD zero = 0, _err;
	op->op = 'd';
	op->s = s;
	op->lpErrno = lpErrno;
	orig_WSPSetSockOpt(s, SOL_SOCKET, SO_DEBUG, &zero, sizeof(BOOL), &_err);

	_handle_overlapped(&op);
	op->res = orig_WSPCloseSocket(s, lpErrno);
	_handle_operation(op);

	sockbuf->s = INVALID_SOCKET;
	sockbuf->userdata = NULL;
	if(sockbuf->rb_in) {
		ring_buffer_free(sockbuf->rb_in);
		sockbuf->rb_in = NULL;
	}
	if(sockbuf->rb_out) {
		ring_buffer_free(sockbuf->rb_out);
		sockbuf->rb_out = NULL;
	}
	return op->res;
}
