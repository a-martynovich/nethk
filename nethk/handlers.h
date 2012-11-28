/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	handlers.h
 * purpose:		WinAPI WSP* functions interception
 */

#pragma once

#ifndef _HOOK_IMPLEMENT
#define HOOK_IMPL(fRET, fNAME, fARGS, fARGNAMES) \
	fRET WSPAPI fNAME##_handler fARGS;
#endif

#define HOOK_DECL(fRET, fNAME, fARGS, fARGNAMES) \
	typedef fRET (WSPAPI * pointer_to_##fNAME)fARGS; \
	extern pointer_to_##fNAME fNAME, orig_##fNAME, my_##fNAME; \
	HOOK_IMPL(fRET, fNAME, fARGS, fARGNAMES)

#define HOOK_INSTALL(fNAME, TBL)\
	fNAME = TBL -> lp##fNAME; \
	orig_##fNAME = fNAME; \
	success = success && Mhook_hook((PVOID*)&orig_##fNAME, fNAME##_handler); \
	TRACE(L"Hook %hs %s: orig=%p hook=%p", #fNAME, success? L"ok": L"fail", orig_##fNAME, fNAME##_handler);
#define HOOK_UNINSTALL(fNAME) \
	success = success && Mhook_unhook((PVOID*)&orig_##fNAME); \
	TRACE(L"Unhook %hs %s", #fNAME, success? L"ok": L"fail");


#define HOOK_DECL_N(fRET, fNAME, fARGS, fARGNAMES) \
	typedef fRET (WSPAPI * pointer_to_##fNAME)fARGS; \
	static pointer_to_##fNAME orig_##fNAME, my_##fNAME, _##fNAME; \
	fRET WSPAPI fNAME##_handler fARGS { \
	if(my_##fNAME) { \
	TRACE(L"calling my_%hs", #fNAME); \
	return my_##fNAME fARGNAMES; } \
		else { TRACE(L"calling %hs", #fNAME); \
		return orig_##fNAME fARGNAMES; } }
#define HOOK_IMPL_N(fNAME) \
	orig_##fNAME = _##fNAME; \
	success = success && Mhook_hook((PVOID*)&orig_##fNAME, fNAME##_handler); \
	if(!success) \
	TRACE(L"Hook %hs %s: orig=%p hook=%p", #fNAME, success? L"ok": L"fail", orig_##fNAME, fNAME##_handler);


/*HOOK_DECL_N(int, WPUCompleteOverlappedRequest,
	(SOCKET s, LPWSAOVERLAPPED lpOverlapped, DWORD dwError, DWORD cbTransf, LPINT lpErrno),
	(s, lpOverlapped, dwError, cbTransf, lpErrno));
*/
HOOK_DECL(SOCKET, WSPAccept,
	(SOCKET s, struct sockaddr *addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData, LPINT lpErrno),
	(s, addr, addrlen, lpfnCondition, dwCallbackData, lpErrno));
HOOK_DECL(int, WSPAddressToString,
	(LPSOCKADDR lpsaAddress, DWORD dwAddressLength,	LPWSAPROTOCOL_INFO lpProtocolInfo, LPWSTR lpszAddressString, LPDWORD lpdwAddressStringLength, LPINT lpErrno	),
	(lpsaAddress, dwAddressLength,lpProtocolInfo, lpszAddressString, lpdwAddressStringLength, lpErrno ));
HOOK_DECL(int, WSPAsyncSelect,
	(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent, LPINT lpErrno	),
	(s, hWnd, wMsg, lEvent, lpErrno	));
HOOK_DECL(int, WSPBind, 
	(SOCKET s, const struct sockaddr *name, int namelen, LPINT lpErrno	),
	(s, name, namelen, lpErrno	));
HOOK_DECL(int, WSPCancelBlockingCall,
	(LPINT lpErrno),
	(lpErrno));
HOOK_DECL(int, WSPCloseSocket,
	(SOCKET s, LPINT lpErrno),
	(s, lpErrno));

HOOK_DECL(int, WSPCleanup,
	(LPINT lpErrno),
	(lpErrno));
HOOK_DECL(int, WSPConnect, 
	(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno),
	(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno));
HOOK_DECL(int, WSPDuplicateSocket,
	(SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFO lpProtocolInfo, LPINT lpErrno),
	(s, dwProcessId, lpProtocolInfo, lpErrno));
HOOK_DECL(int, WSPEnumNetworkEvents,
	(SOCKET s, WSAEVENT hEventObject,LPWSANETWORKEVENTS lpNetworkEvents, LPINT lpErrno),
	(s, hEventObject, lpNetworkEvents, lpErrno));
HOOK_DECL(int, WSPEventSelect,
	(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents, LPINT lpErrno),
	(s, hEventObject, lNetworkEvents, lpErrno));
HOOK_DECL(BOOL, WSPGetOverlappedResult,
	(SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags, LPINT lpErrno),
	(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags, lpErrno));
HOOK_DECL(int, WSPGetPeerName,
	(SOCKET s, struct sockaddr *name, LPINT namelen, LPINT lpErrno),
	(s, name, namelen, lpErrno));
HOOK_DECL(int, WSPGetSockName,
	(SOCKET s, struct sockaddr *name, LPINT namelen, LPINT lpErrno),
	(s, name, namelen, lpErrno));
HOOK_DECL(int, WSPGetSockOpt,
	(SOCKET s, int level, int optname, char *optval, LPINT optlen, LPINT lpErrno),
	(s, level, optname, optval, optlen, lpErrno));
HOOK_DECL(BOOL, WSPGetQOSByName,
	(SOCKET s, LPWSABUF lpQOSName, LPQOS lpQOS, LPINT lpErrno),
	(s, lpQOSName, lpQOS, lpErrno));
HOOK_DECL(int, WSPIoctl,
	(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer,	LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,	LPWSAOVERLAPPED lpOverlapped,	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	LPWSATHREADID lpThreadId, LPINT lpErrno),
	(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,	lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno));
HOOK_DECL(SOCKET, WSPJoinLeaf,
	(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData,	LPQOS lpSQOS, LPQOS lpGQOS, DWORD dwFlags, LPINT lpErrno),
	(s, name, namelen, lpCallerData, lpCalleeData,	lpSQOS, lpGQOS, dwFlags, lpErrno));
HOOK_DECL(int, WSPListen,
	(SOCKET s, int backlog, LPINT lpErrno),
	(s, backlog, lpErrno));
HOOK_DECL(int, WSPRecv,	
	(SOCKET s, LPWSABUF buffers, DWORD	buffer_count, LPDWORD	bytes_received, LPDWORD flags,	LPWSAOVERLAPPED overlapped,	LPWSAOVERLAPPED_COMPLETION_ROUTINE	completion_routine,	LPWSATHREADID	thread_id, LPINT	errno1),
	(		s,			buffers,		buffer_count,			bytes_received,			flags,					overlapped,										completion_routine,					thread_id,			errno1));
HOOK_DECL(int, WSPRecvDisconnect,
	(SOCKET s, LPWSABUF lpInboundDisconnectData, LPINT lpErrno),
	(s, lpInboundDisconnectData, lpErrno));
HOOK_DECL(int, WSPRecvFrom,
	(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,	LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr *lpFrom,	LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	LPWSATHREADID lpThreadId, LPINT lpErrno	),
	(s, lpBuffers, dwBufferCount,	lpNumberOfBytesRecvd, lpFlags, lpFrom,	lpFromlen, lpOverlapped,	lpCompletionRoutine,	lpThreadId, lpErrno	));
HOOK_DECL(int, WSPSelect,
	(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout, LPINT lpErrno ),
	(nfds, readfds, writefds, exceptfds, timeout, lpErrno ));
HOOK_DECL(int, WSPSend,
	(SOCKET s, LPWSABUF p_buffers, DWORD buffer_count,	LPDWORD p_bytes_sent, DWORD flags,	LPWSAOVERLAPPED p_overlapped,	LPWSAOVERLAPPED_COMPLETION_ROUTINE p_completion_routine,	LPWSATHREADID p_thread_id, LPINT p_errno),
	(s, p_buffers, buffer_count,	p_bytes_sent, flags,	p_overlapped,	p_completion_routine,	p_thread_id, p_errno));
HOOK_DECL(int, WSPSendDisconnect,
	(SOCKET s, LPWSABUF lpOutboundDisconnectData, LPINT lpErrno	),
	(s, lpOutboundDisconnectData, lpErrno));
HOOK_DECL(int, WSPSendTo,
	(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,	LPDWORD lpNumberOfBytesSent, DWORD dwFlags,	const struct sockaddr *lpTo, int iTolen,	LPWSAOVERLAPPED lpOverlapped,	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	LPWSATHREADID lpThreadId, LPINT lpErrno	),
	(s, lpBuffers, dwBufferCount,	lpNumberOfBytesSent, dwFlags,	lpTo, iTolen,	lpOverlapped,	lpCompletionRoutine,	lpThreadId, lpErrno	));
HOOK_DECL(int, WSPSetSockOpt,
	(SOCKET s, int level, int optname, const char *optval, int optlen,	LPINT lpErrno	),
	(s, level, optname, optval, optlen,	lpErrno	));
/*HOOK_DECL(int, WSPStartup,
	(WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo,	WSPUPCALLTABLE UpcallTable,	LPWSPPROC_TABLE lpProcTable),
	(wVersionRequested, lpWSPData, lpProtocolInfo,	UpcallTable,	lpProcTable));*/
HOOK_DECL(int, WSPShutdown,
	(SOCKET s, int how, LPINT lpErrno),
	(s, how, lpErrno));
HOOK_DECL(SOCKET, WSPSocket,
	(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo,	GROUP g, DWORD dwFlags, LPINT lpErrno),
	(af, type, protocol, lpProtocolInfo, g, dwFlags, lpErrno));
HOOK_DECL(int, WSPStringToAddress,
	(LPWSTR AddressString, INT AddressFamily, LPWSAPROTOCOL_INFO lpProtocolInfo, LPSOCKADDR lpAddress, LPINT lpAddressLength, LPINT lpErrno	),
	(AddressString, AddressFamily, lpProtocolInfo, lpAddress, lpAddressLength, lpErrno	));

BOOL WSPAPI _my_WSPGetOverlappedResult (SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags, LPINT lpErrno);

int WSPAPI _my_WSPSend (
	SOCKET s, 
	LPWSABUF lpBuffers, 
	DWORD dwBufferCount,	
	LPDWORD lpNumberOfBytesRecvd, 
	DWORD flags,	
	LPWSAOVERLAPPED lpOverlapped,	
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
	LPWSATHREADID lpThreadId, 
	LPINT lpErrno );

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
	LPINT lpErrno );

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
	LPINT lpErrno	);

int WSPAPI _my_WSPRecv	(
	SOCKET s, 
	LPWSABUF lpBuffers, 
	DWORD dwBufferCount,	
	LPDWORD lpNumberOfBytesRecvd, 
	LPDWORD lpFlags, 
	LPWSAOVERLAPPED lpOverlapped,	
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,	
	LPWSATHREADID lpThreadId, 
	LPINT lpErrno	);

int WSPAPI _my_WSPConnect	(
	SOCKET s, 
	const struct sockaddr *name, 
	int namelen, 
	LPWSABUF lpCallerData, 
	LPWSABUF lpCalleeData, 
	LPQOS lpSQOS, 
	LPQOS lpGQOS, 
	LPINT lpErrno	);

int WSPAPI _my_WSPCloseSocket	(
	SOCKET s, 
	LPINT lpErrno				);

typedef DWORD (WINAPI * lpWaitForSingleObjectEx) (
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds,
	_In_ BOOL bAlertable	);
extern lpWaitForSingleObjectEx orig_WaitForSingleObjectEx;
DWORD WINAPI _my_WaitForSingleObjectEx(
	_In_  HANDLE hHandle,
	_In_  DWORD dwMilliseconds,
	_In_ BOOL bAlertable	);
