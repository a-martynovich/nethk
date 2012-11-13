/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk_load
 * filename:	nethk_load.c
 * purpose:		injects dll to a target process
 */


#include "stdafx.h"
#pragma warning(disable: 4996)			// "sprintf is unsafe"

#include <strsafe.h>
#include <TlHelp32.h>

void _error_message(LPTSTR lpszFunction) 
{ 
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError(); 
	static HMODULE m = LoadLibrary(L"wininet.dll");
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, //|
		//FORMAT_MESSAGE_FROM_HMODULE,
		NULL,//m,
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
	//MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 
	//wprintf((LPCTSTR)lpDisplayBuf);	
	WriteConsoleW(hConsole, lpDisplayBuf, wcslen((LPCWSTR)lpDisplayBuf), &dw, NULL);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	//ExitProcess(dw); 
}

typedef LONG ( NTAPI *_NtSuspendProcess )( IN HANDLE ProcessHandle ); 
typedef LONG ( NTAPI *_NtResumeProcess )( IN HANDLE ProcessHandle );

HMODULE InjectDLL(DWORD process_id, LPCTSTR dll_path, BOOL eject) {
	static HANDLE process_handle;
	static void* remote_base;
	static DWORD exit_code;
	static bool success;
	static HMODULE kernel32;
	_NtSuspendProcess NtSuspendProcess = 0; 
	_NtResumeProcess NtResumeProcess = 0; 
	NtSuspendProcess = (_NtSuspendProcess) GetProcAddress( GetModuleHandle( L"ntdll" ), "NtSuspendProcess" ); 
	NtResumeProcess = (_NtResumeProcess) GetProcAddress( GetModuleHandle( L"ntdll" ), "NtResumeProcess" ); 

	if(eject==FALSE) {
		// Open Process
		process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);	
		if (process_handle == 0) {
			_error_message(L"OpenProcess");
			return NULL;
		}

		// Allocate space for string to contain the DLL Path
		SIZE_T path_length = (wcslen(dll_path)+1)*2;
		void* remote_buffer = VirtualAllocEx(process_handle, NULL, path_length, MEM_COMMIT, PAGE_READWRITE);

		success = false;
		exit_code = WAIT_FAILED;
		if (remote_buffer != NULL) {
			SIZE_T bytes_written = 0;
			WriteProcessMemory(process_handle, remote_buffer, dll_path, path_length, &bytes_written);
			if (bytes_written == path_length) {
				DWORD thread_id = 0; 
				kernel32 = GetModuleHandleA("Kernel32");
				LPTHREAD_START_ROUTINE remote_lla = reinterpret_cast<LPTHREAD_START_ROUTINE> (GetProcAddress(kernel32, "LoadLibraryW"));
				if (remote_lla != NULL) {
					NtSuspendProcess(process_handle);
					HANDLE thread = CreateRemoteThread(process_handle, NULL, 0, remote_lla, reinterpret_cast<void*> (remote_buffer), 0, &thread_id);
					if (thread != NULL && thread_id != 0) {
						WaitForSingleObject(thread, 5000);
						GetExitCodeThread(thread, &exit_code);
						CloseHandle(thread);
					}
					else {
						_error_message(L"CreateRemoteThread");
					}
					NtResumeProcess(process_handle);
				}
			}
			else {
				_error_message(L"WriteProcessMemory");
			}
			VirtualFreeEx(process_handle, remote_buffer, path_length, MEM_RELEASE);
		}
		else {
			_error_message(L"VirtualAllocEx");
		}

		if (exit_code == WAIT_FAILED || exit_code == WAIT_ABANDONED || exit_code == WAIT_TIMEOUT) {
			// Thread didn't complete
			success = false;
			printf("error: remote thread exited with code %d\n", exit_code);
		} else if (exit_code < 0x1000) {
			// LoadLibraryFailed
			success = false;
			printf("error: LoadLibrary failed\n");
		} else {
			success = true;
			remote_base = reinterpret_cast<void*> (exit_code);
		}

		if (success) return reinterpret_cast<HMODULE> (remote_base);
		return NULL; // Fail
	}
	else {
		if(!success) return false;
		success = FALSE;
		while(!success) {
			LPTHREAD_START_ROUTINE remote_lla = reinterpret_cast<LPTHREAD_START_ROUTINE> (GetProcAddress(kernel32, "FreeLibrary"));
			if (remote_lla != NULL) {
//#ifdef _M_X64
				remote_base = NULL;
				HANDLE hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, process_id ); 
				MODULEENTRY32 me32; 
				if( hModuleSnap == INVALID_HANDLE_VALUE ) { 
					_error_message(L"CreateToolhelp32Snapshot");
					return NULL; 
				} 
				me32.dwSize = sizeof( MODULEENTRY32 ); 
				if( !Module32First( hModuleSnap, &me32 ) ) { 
					_error_message( L"Module32First" );  // Show cause of failure 
					CloseHandle( hModuleSnap );     // Must clean up the snapshot object! 
					return NULL; 
				}
				do {
					if(!wcscmp(me32.szModule, L"nethk.dll")) {
						remote_base = me32.hModule;
						break;
					}
				} while( Module32Next( hModuleSnap, &me32 ) ); 
				if(!remote_base) {
					printf("error: cannot find nethk.dll in process memory\n");
					CloseHandle(hModuleSnap);
					return NULL;
				}
				CloseHandle(hModuleSnap);
//#endif
				DWORD thread_id; 
				//NtSuspendProcess(process_handle);
				HANDLE thread = CreateRemoteThread(process_handle, NULL, 0, remote_lla, remote_base, 0, &thread_id);
				if (thread != NULL && thread_id != 0) {
					WaitForSingleObject(thread, 1000);
					GetExitCodeThread(thread, &exit_code);
					CloseHandle(thread);
				} else {
					_error_message(L"CreateRemoteThread");
				}
				//NtResumeProcess(process_handle);
			} else {
				_error_message(L"GetProcAddress");
			}

			if (exit_code == WAIT_FAILED || exit_code == WAIT_ABANDONED || exit_code == WAIT_TIMEOUT) {
				// Thread didn't complete
				success = false;
				printf("error: remote thread exited with code %d\n", exit_code);
			} else if (exit_code != TRUE && exit_code!=FALSE) {
				// FreeLibraryFailed
				success = false;
				printf("error: FreeLibrary failed\n");
			} else {
				success = true;				
				return NULL;
			}
			Sleep(100);
		}
		return NULL;
	}
}

char* _format_data(DWORD dwFileSize, char* buf) {
	size_t columns = 16, rows = dwFileSize/columns + (dwFileSize%columns? 1: 0);
	if(dwFileSize >0 && rows==0) rows = 1;
	else if(dwFileSize==0) return 0;
	char* output = new char[rows*80], *_output = output;
	ZeroMemory(output, rows*80);
	for(size_t i=0; i<rows; i++) {
		for(size_t j=0; j<columns; j++) {
			size_t k = i*columns+j;
			UCHAR symbol = 0;
			if(k < dwFileSize) 
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
			if(k >= dwFileSize) break;

			output+=sprintf(output, "%02x ", (UCHAR)buf[k]);
		}
		output+=sprintf(output, "\n");
	}
	return _output;
}

DWORD pid = 0;
DWORD WINAPI ReadFromNethk_worker(LPVOID lpParam) {
	UNREFERENCED_PARAMETER(lpParam);
	char sPipeName[256];
	sprintf(sPipeName, "\\\\.\\pipe\\Nethk%d", pid);
	DWORD nRead, i=0, s = 1024*1024; 
	char* buffer = new char[s];
	WCHAR addr[256];

	while(true) {		
		HANDLE hPipe = CreateNamedPipeA(sPipeName, 
			PIPE_ACCESS_INBOUND, 
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 
			PIPE_UNLIMITED_INSTANCES, 
			0, 0, 200, NULL);

		HANDLE h = OpenEvent(EVENT_MODIFY_STATE, FALSE, TEXT("Hello"));
		SetEvent(h); 
		printf("event fired\n");
		CloseHandle(h);

		if (!ConnectNamedPipe(hPipe, NULL))
			return FALSE;		
		while (true)
		{			
			BOOL b = ReadFile(hPipe, buffer, s, &nRead, NULL);
			if(GetLastError() == ERROR_MORE_DATA)
				printf("+");
			else if(!b) break;
			//buffer[nRead] = 0;			
			//printf("<%d read %d bytes>\n", i++, nRead);		
			char* buf = (char*)buffer;
			int alen = (unsigned char)buf[1];			
			alen *= 2;
			memcpy(addr, buf+2, alen);
			addr[alen] = L'\0';
			switch(buf[0]) {
			case 'r':
			case 'f':
				wprintf(L"--- receive %d bytes from %s---\n", nRead-2-alen, addr);
				break;
			case 's':
			case 't':
				wprintf(L"--- send %d bytes to %s---\n", nRead-2-alen, addr);
				break;
			}
			
			char* output = _format_data(nRead-2-alen, buf+2+alen);
			printf("%s\n", output);
			delete[] output;			
		}
	}
}

void ReadFromNethk(DWORD process_id) {
	DWORD dwThreadID;
	HANDLE hThread = CreateThread(
		NULL,              // default security
		0,                 // default stack size
		ReadFromNethk_worker,        // name of the thread function
		NULL,              // no thread parameters
		0,                 // default startup flags
		&dwThreadID);
	printf("\nPRESS q TO EXIT\n");
	while(_getch()!='q');
	printf("EXITING... CTRL+C TO ABORT\n");
}

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int _tmain(int argc, _TCHAR* argv[])
{	
	WCHAR fname[256];
	WCHAR* module = new WCHAR[256];
	BOOL found_dll = FALSE;
	DWORD s = GetModuleFileName(NULL, fname, 256);
	if(s) {
		wsprintf(module, L"%s/../nethk.dll", fname);
		if(FileExists(fname)) {
			printf("nethk.dll found\n");
			found_dll = TRUE;
		}
	}
	//DWORD pid = 0;
	if(argc == 1) {
		if(found_dll == FALSE) {
			printf("Not enough args\n");
			return 2;
		}
		else {			
			printf("Enter process pid: ");
			scanf("%d", &pid);
		}
	}
	else if(argc == 2) {		
		if(found_dll == FALSE) {
			module = argv[1];
			printf("Enter process pid: ");
			scanf("%d", &pid);
		}
		else pid = _wtoi(argv[1]);
	}
	else {
		pid = _wtoi(argv[2]);
		module = argv[1];
	}
	
	wprintf(L"Injecting dll %s...\n", module);
	if(InjectDLL(pid, module, FALSE)) {
		printf("Success!");
		ReadFromNethk(pid);	
		InjectDLL(pid, module, TRUE);		
	}
	else {
		printf("Cannot inject DLL\n");		
	}
	printf("PRESS q TO EXIT\n");	
	while(_getch()!='q');
}

