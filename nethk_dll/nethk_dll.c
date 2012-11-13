/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	nethk_dll.c
 * purpose:		dll entrypoint and I/O control
 */

#include <stdint.h>
#include <ws2spi.h>
//#include "mhook/mhook.h"
#include "../nethk/mincrt/mincrt.h"
#include "../nethk/nethk.h"

#if defined(_TRACE)
#define TRACE odprintfW
#else 
#define TRACE(...)
#endif

#ifdef OUTPUT_PIPE
HANDLE hPipe = 0;
char sPipeName[256];
/*
 * ThreadProc: constantly tries to open named pipe. When the pipe gets closed
 * it ThreadProc waits for "Hello" event which should be emitted by nethk_load
 * each time it creates the pipe.
 */
DWORD WINAPI ThreadProc(LPVOID lpParam) {
	UNREFERENCED_PARAMETER(lpParam);		
	//ovl.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	while(TRUE) {		
		HANDLE h;
		Sleep(100);
		if(hPipe) {
			TRACE(L"smth is wrong. the pipe was not closed");
		}
		TRACE(L"--- opening pipe %hs---", sPipeName);
		hPipe = CreateFileA(sPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if(hPipe == INVALID_HANDLE_VALUE) { 
			TRACE(L"open pipe failed: %d", GetLastError());			
		}
		else {
			TRACE(L"pipe is open");			
		}		
		h = CreateEvent(NULL, FALSE, FALSE, TEXT("Hello"));
		WaitForSingleObject(h, INFINITE);
		CloseHandle(h);			
	}
	return 0;
}
#endif


/*
 * _format_data: formats input data for nice output. The format is 
 * as follows:
 * 
 * aaaaaaaaaaaaaaaa <TAB> hh hh hh hh hh hh hh hh hh hh hh hh hh hh hh hh 
 * 
 * where a is <a> buffer character if it is printable, and a dot (.)
 * otherwise, and <hh> is a hex value of the character.
 */
char* _format_data(DWORD dwDataLength, BYTE* buf) {
	size_t columns = 16, rows = dwDataLength/columns + (dwDataLength%columns? 1: 0);
	static char* _output=0;
	char* output;
	static size_t output_size = 0;
	size_t i,j,k;

	if(dwDataLength >0 && rows==0) rows = 1;
	else if(dwDataLength==0) return 0;
	if(output_size < rows*80) {
		output_size = rows*80;
		if(!_output) _output = mem_alloc(output_size);
		else mem_realloc(&_output, output_size);
	}
	output = _output;

	mem_set(output, 0, output_size);
	for(i=0; i<rows; i++) {
		for(j=0; j<columns; j++) {
			UCHAR symbol = '•';
			k = i*columns+j;
			if(k < dwDataLength) 
				symbol = buf[k];

			if(str_isprint(symbol)) {
				if(str_isspace(symbol))
					output+=sprintf(output, " ");
				else output+=sprintf(output, "%c", symbol);
			}
			else output+=sprintf(output, "•");
			//printf(" ");
		}
		output += sprintf(output, "            ");
		for(j=0; j<columns; j++) {
			k = i*columns+j;
			if(k >= dwDataLength) 
				break;

			output+=sprintf(output, "%02x ", buf[k]);
		}
		output+=sprintf(output, "\n");
	}
	i = output - _output;
	return _output;
}

#ifdef OUTPUT_PIPE
extern HANDLE hPipe;
DWORD WINAPI _write_pipe(char* buffer, DWORD len) {
	DWORD written = 0;
	size_t i=0;
	static OVERLAPPED ovl;
	mem_set(&ovl, 0, sizeof(ovl));

	if(hPipe != INVALID_HANDLE_VALUE && hPipe != 0) {
		BOOL b = WriteFile(hPipe, buffer, len, &written, &ovl);			
		DWORD e = GetLastError();
		TRACE(L"message written %d bytes\n", len);		
		if(e != ERROR_IO_PENDING && e != NO_ERROR && !b) {
			if(e == ERROR_INVALID_USER_BUFFER || e == ERROR_NOT_ENOUGH_MEMORY) {
				TRACE(L"--- too many overlapped writes");
			}
			else {
				TRACE(L"--- pipe is closed: %d ---\n", e);
				CloseHandle(hPipe);
				hPipe = 0;
			}
		}			
	}
	return 0;
}
#endif


/*
 * _create_pipe:
 *	Creates a thread that tries to keep write-only process pipe open.
 * Arguments: 
 *	pipe_name: the name of the pipe without \\.\pipe\ prefix
 * Returns: 
 *  TRUE on success, FALSE otherwise
*/
#ifdef OUTPUT_PIPE
HANDLE hThread;
DWORD dwThreadID;

BOOL _create_pipe(LPCSTR pipe_name) {
	sprintf(sPipeName, "\\\\.\\pipe\\%s", pipe_name);
	hThread = CreateThread(
		NULL,              // default security
		0,                 // default stack size
		ThreadProc,        // name of the thread function
		NULL,              // no thread parameters
		0,                 // default startup flags
		&dwThreadID);	
	return (hThread!=NULL && hThread!=INVALID_HANDLE_VALUE);
}
#endif

enum nethk_filter my_nethk_filter(const nethk_operation* op) {
	static BYTE* data = NULL;
	static DWORD datalen = 0;
	DWORD addrlen=255, _datalen;
	WCHAR addr[256], *operation_string, *protostring;
	char* formatted_data = NULL;

	switch(nethk_get_operation(op)) {
	case OP_SEND:
		operation_string = L"send to";
		break;
	case OP_RECV:
		operation_string = L"recv from";
		break;
	case OP_CONNECT:
		operation_string = L"connect to";
		break;
	case OP_DISCONNECT:
		operation_string = L"disconnect from";
		break;
	case OP_ACCEPT:
		operation_string = L"accept";
		break;
	};
	
	switch(nethk_get_operation(op)) {
	case OP_SEND:		
	case OP_RECV: {		
		if(nethk_get_data(op, NULL, &_datalen)==E_SUCCESS) {		// get data length first
			if(_datalen) {
				if(!data) {
					data = mem_alloc(_datalen);
					datalen = _datalen;
				}
				else if (_datalen > datalen) {
					mem_realloc(&data, _datalen);
					datalen = _datalen;
				}
				mem_set(data, 0, datalen);
				nethk_get_data(op, data, &_datalen);
				formatted_data = _format_data(_datalen, data);
			}
		}		
	}
	case OP_CONNECT:
	case OP_DISCONNECT:
	case OP_ACCEPT: {
		nethk_get_address_string(op, addr, &addrlen);
	}
	};	
	switch(op->proto) {
	case IPPROTO_ICMP:
		protostring = L"ICMP"; 
		break;
	case IPPROTO_TCP:
		protostring = L"TCP";
		break;
	case IPPROTO_UDP:
		protostring = L"UDP";
		break;
	case IPPROTO_IP:
		protostring = L"(unknown IP proto)";
		break;
	}
	TRACE(L"***\t%s %s %s\t***", operation_string, protostring, addr);
	if(formatted_data) {
		DWORD l = str_len(formatted_data), i;
		TRACE(L"***\t%d bytes\t***", _datalen);		
		for(i = 0; i<l; i+=512) {
			char c = formatted_data[i+512 > l? l+1: i+512];
			formatted_data[i+512 > l? l+1: i+512] = 0;
			OutputDebugStringA(formatted_data+i);
			formatted_data[i+512 > l? l+1: i+512] = c;
		}
		OutputDebugStringA("\n");
	}
	return FI_PASS;
};
/*
 * DllMain: dll entrypoint. Initializes mincrt memory, installs hooks,
 * opens named pipe if OUTPUT_PIPE is defined.
 */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	BOOL success;
	static nethk_handler my_handler;
#ifdef OUTPUT_PIPE
	CHAR pid_str[16];
#endif
	UNREFERENCED_PARAMETER(hinst);
	UNREFERENCED_PARAMETER(reserved);	

	if (dwReason == DLL_PROCESS_ATTACH) {
		TRACE(L"nethk starting...");		
		success = nethk_install();

		if (success == TRUE) {
			TRACE(L"--- hook ok ---");
		}
		else {
			TRACE(L"--- cannot hook ---");			
			return FALSE;
		}
		my_handler.proto = IPPROTO_TCP;
		my_handler.family = IPPROTO_IP;
		my_handler.filter = my_nethk_filter;
		nethk_add_handler(&my_handler);
#ifdef OUTPUT_PIPE
		sprintf(pid_str, "Nethk%d", GetCurrentProcessId());
		_create_pipe(pid_str);
#endif
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		success = nethk_uninstall();
		TRACE(L"--- removed: %s ---\n", success==TRUE? L"SUCCESS": L"FAIL");		
#ifdef OUTPUT_PIPE
		if(hThread && hThread!=INVALID_HANDLE_VALUE) {
			TerminateThread(hThread, 0);
		}		
#endif
	}
	return TRUE;
}
