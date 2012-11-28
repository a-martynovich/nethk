//=============================================================================

#include "mincrt.h"

//-----------------------------------------------------------------------------

int mincrt_init(size_t initial_mem_len)
{
	return _mincrt_mem_init(initial_mem_len);
}

//-----------------------------------------------------------------------------

int mincrt_deinit()
{
	return _mincrt_mem_deinit();
}

//=============================================================================

void _error_message(LPWSTR lpszFunction) 
{ 
	// Retrieve the system error message for the last-error code
	LPWSTR lpMsgBuf = mem_alloc(1024*sizeof(WCHAR)),
		lpDisplayBuf = mem_alloc(1024*sizeof(WCHAR));
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

	//wsprintfW(lpDisplayBuf, L"%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf); 
	//TRACE(lpDisplayBuf);
	odprintfW(L"%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf);
	mem_free(lpMsgBuf);
	mem_free(lpDisplayBuf);
}
