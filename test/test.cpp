/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		test
 * filename:	test.c
 * purpose:		constantly sends HTTP requests to random sites and reads responses.
 */

#include "stdafx.h"
#include <strsafe.h>

void _error_message(LPTSTR lpszFunction) 
{ 
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError(); 
	static HMODULE m = LoadLibrary(L"wininet.dll");

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_HMODULE,
		m,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0, NULL );

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
	StringCchPrintf((LPTSTR)lpDisplayBuf, 
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s\n"), 
		lpszFunction, dw, lpMsgBuf); 
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 
	//wprintf((LPCTSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	//ExitProcess(dw); 
}

static int _check_network()
{
	HINTERNET	h_internet;
	int			result = 0;

	h_internet = InternetOpen(
		TEXT("test-user-agent"), INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0
		);

	if (h_internet)
	{
		HINTERNET	h_connection;

		h_connection = InternetConnect(
			h_internet, TEXT("habrahabr.ru"), INTERNET_DEFAULT_HTTP_PORT,
			0, 0, INTERNET_SERVICE_HTTP, 0, 0
			);
		BOOL bHttpDecoding = TRUE;
		InternetSetOption(h_internet, INTERNET_OPTION_HTTP_DECODING, &bHttpDecoding, sizeof(bHttpDecoding) );
		if (h_connection)
		{
			HINTERNET	h_request;

			h_request = HttpOpenRequest(
				h_connection, TEXT("GET"), TEXT("/"), 0, 0, 0, 0, 0
				);

			if (h_request) {
				if (HttpSendRequest(h_request, 0, 0, 0, 0))
				{
					result = 1;
					char szSizeBuffer[32];
					//DWORD dwLengthSizeBuffer = sizeof(szSizeBuffer), dwFileSize; 
					//BOOL bQuery = HttpQueryInfoA(h_request,HTTP_QUERY_CONTENT_LENGTH, szSizeBuffer, &dwLengthSizeBuffer, NULL) ;
					//if(bQuery==TRUE) {
						//dwFileSize=atol(szSizeBuffer);
						DWORD dwFileSize = 1024*1024;
						LPSTR szContents = new CHAR[dwFileSize];
						DWORD dwBytesRead;
						BOOL bRead;
						while(bRead = InternetReadFile(h_request, szContents, dwFileSize, &dwBytesRead)) {
							if(!dwBytesRead) break;
							result = 2;
							char* buf = szContents;
							printf("***\t%d bytes\t***\n", dwBytesRead);
							const size_t total_cols = 80, cols = 16;
							size_t columns = cols, rows = dwBytesRead/columns + (dwBytesRead%columns? 1: 0);
							if(dwBytesRead>0 && rows==0) rows = 1;
							char* output = new char[rows*total_cols], *_output = output;
							for(size_t i=0; i<rows; i++) {
								for(size_t j=0; j<columns; j++) {
									size_t k = i*columns+j;
									UCHAR symbol = 0;
									if(k < dwBytesRead) 
										symbol = (UCHAR)buf[k];

									if(isprint(symbol)) {
										if(isspace(symbol))
											output+=sprintf(output, " ");
										else output+=sprintf(output, "%c", symbol);
									}
									else output+=sprintf(output, ".");
									//printf(" ");
								}
								output += sprintf(output, "\t");
								for(size_t j=0; j<columns; j++) {
									size_t k = i*columns+j;
									if(k >= dwBytesRead) break;

									output+=sprintf(output, "%02x ", (UCHAR)buf[k]);
								}
								output+=sprintf(output, "\n");
							}
							printf("%s\n***\t***\n", _output);
							delete[] _output;
						} /*else {
							_error_message(L"InternetReadFile");
						}*/
					/*} else {
						_error_message(L"HttpQueryInfo");
					}*/
				} else {
					_error_message(L"HttpSendRequest");
				}				
				InternetCloseHandle(h_request);
			} else {
				_error_message(L"HttpOpenRequest");
			}
			InternetCloseHandle(h_connection);
		} else {
			_error_message(L"InternetConnect");
		}				
		InternetCloseHandle(h_internet);
	} else {
		_error_message(L"InternetOpen");
	}

	return result;
}

int _tmain1(int argc, _TCHAR* argv[])
{
	char s[256];
	int i=0;
	sprintf(s, "nethk test PID=%d", GetCurrentProcessId());
	SetConsoleTitleA(s);			
	
	HMODULE m = NULL;
	if(i%2==0 && argc > 1) {
		m = LoadLibrary(argv[1]);
		if(!m) {
			printf("cannot load nethk.dll\n");
		} else printf("***\tloaded nethk.dll\t***\n");
	}

	while(true) {
/*#ifdef USE_NETHK
		HMODULE m = NULL;
		if(i%2==0 && argc > 1) {
			m = LoadLibrary(argv[1]);
			if(!m) {
				printf("cannot load nethk.dll\n");
			} else printf("***\tloaded nethk.dll\t***\n");
		}
#endif*/
		printf("sending request (%d): \n", i++);
		char* s;
		int r = _check_network();
		if(r==0) s="ERROR";
		else if(r==1) s="NO CONTENT";
		else s="OK";
		printf("\n[%s]\n", s);
/*#ifdef USE_NETHK		
		if(i%2==1) {
			if(m && !FreeLibrary(m)) {
				printf("cannot unload nethk.dll\n");
			} else printf("***\tunloaded nethk.dll\t***\n");
		}
#endif*/
		Sleep(1000);
	}
	return 0;
}

