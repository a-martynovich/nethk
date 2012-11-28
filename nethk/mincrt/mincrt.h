//=============================================================================

#ifndef __MINCRT_H_INCLUDED__
#define __MINCRT_H_INCLUDED__

//-----------------------------------------------------------------------------

#include "mincrt_mem.h"
#include "mincrt_str.h"

#include <stdint.h>

//-----------------------------------------------------------------------------

#define min_val(a, b)	(((a) < (b)) ? (a) : (b))
#define max_val(a, b)	(((a) > (b)) ? (a) : (b))

//-----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------

/*
 * Description:
 *	Initialize mincrt library.
 *
 * Parameters:
 *	initial_mem_len - Size of the initial memory.
 *
 * Return value:
 *	If the function succeeds, the return value is nonzero.
 *	If the function fails, the return value is zero.
 */
int mincrt_init(size_t initial_mem_len);

/*
 * Description:
 *	Deinitialize mincrt library.
 *
 * Parameters:
 *	None.
 *
 * Return value:
 *	If the function succeeds, the return value is nonzero.
 *	If the function fails, the return value is zero.
 */
int mincrt_deinit();
void _error_message(wchar_t* lpszFunction);
//-----------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

//-----------------------------------------------------------------------------
#define assert(e) if(!(e)) { odprintfA("FATAL: assertion %s failed", #e); DebugBreak(); }


#ifndef ODPRINTF

#if 1 //defined(_DEBUG) && defined(_TRACE)
#include <windows.h>
#include "mincrt_str.h"

#if defined(_TRACE_FILE)
extern FILE* _log;
#endif
extern CRITICAL_SECTION CriticalSection;
__inline void odprintfA(PCSTR format, ...) {
	CHAR _buf[1024];		// this is the maximum size supported by wvsprintf
	va_list	args;	
	int len;
	va_start(args, format);	
	//EnterCriticalSection(&CriticalSection);
	len = wvsprintfA(_buf, format, args);//wvnsprintfA(_buf, 256-2, format, args);
	if (len > 0) {
		_buf[len++] = '\r';
		_buf[len++] = '\n';
		_buf[len] = '\0';
		OutputDebugStringA(_buf);
#if defined(_TRACE_FILE)
		fputs(_buf, _log);
		fflush(_log);
#endif
	}
	//LeaveCriticalSection(&CriticalSection);
}

__inline void odprintfW(PCWSTR format, ...) {
	WCHAR _buf[1024];	// this is the maximum size supported by wvsprintf
	va_list	args;	
	int len;
	va_start(args, format);	
	//EnterCriticalSection(&CriticalSection);
	len = wvsprintfW(_buf, format, args);//wvnsprintfW(_buf, 256-2, format, args);
	if (len > 0) {
		_buf[len++] = L'\r';
		_buf[len++] = L'\n';
		_buf[len] = L'\0';
		OutputDebugStringW(_buf);
#if defined(_TRACE_FILE)
		fputws(_buf, _log);
		fflush(_log);
#endif
	}
	//LeaveCriticalSection(&CriticalSection);
}


#else
#define ODPRINTF(a) NULL
#define odprintfA(...) NULL
#define odprintfW(...) NULL
#endif
#endif

#endif //__MINCRT_H_INCLUDED__

//=============================================================================