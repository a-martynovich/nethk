/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	mhook.c
 * purpose:		runtime code hooking
 */

/*
* Copyright (c) 2007-2012, Marton Anka
* Portions Copyright (c) 2007, Matt Conover
*
* Permission is hereby granted, free of charge, to any person obtaining a copy 
* of this software and associated documentation files (the "Software"), to deal 
* in the Software without restriction, including without limitation the rights to 
* use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
* of the Software, and to permit persons to whom the Software is furnished to do 
* so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all 
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
* INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
* PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
* CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
* OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <windows.h>
#include <tlhelp32.h>
#include "mhook.h"
#include "../disasm/disasm.h"
#include "mincrt/mincrt_mem.h"
#include "mincrt/mincrt.h"

#define DEBUG(...)

#ifdef _TRACE_MHOOK
#define TRACE odprintfW
#else
#define TRACE(...)
#endif

//=========================================================================
#ifndef cntof
#define cntof(a) (sizeof(a)/sizeof(a[0]))
#endif

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a!=INVALID_HANDLE_VALUE)&&(a!=NULL))
#endif

//=========================================================================
#ifndef gle
#define gle GetLastError
#endif

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES	32
#define MHOOKS_MAX_RIPS			 4

//=========================================================================
// The trampoline structure - stores every bit of info about a hook
typedef struct _MHOOKS_TRAMPOLINE {
	PBYTE	pSystemFunction;								// the original system function
	DWORD	cbOverwrittenCode;								// number of bytes overwritten by the jump
	PBYTE	pHookFunction;									// the hook function that we provide
	BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// placeholder for code that jumps to the hook function
	BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// placeholder for code that holds the first few
															//   bytes from the system function and a jump to the remainder
															//   in the original location
	BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// placeholder for unmodified original code
															//   (we patch IP-relative addressing)
}MHOOKS_TRAMPOLINE;


//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
typedef struct _MHOOKS_RIPINFO
{
	DWORD	dwOffset;
	S64		nDisplacement;
} MHOOKS_RIPINFO;

typedef struct _MHOOKS_PATCHDATA
{
	S64				nLimitUp;
	S64				nLimitDown;
	DWORD			nRipCnt;
	MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS];
}MHOOKS_PATCHDATA;

//=========================================================================
// Global vars
static BOOL g_bVarsInitialized = FALSE;
static CRITICAL_SECTION g_cs;
static MHOOKS_TRAMPOLINE* g_pHooks[MHOOKS_MAX_SUPPORTED_HOOKS];
static DWORD g_nHooksInUse = 0;
static HANDLE* g_hThreadHandles = NULL;
static DWORD g_nThreadHandles = 0;
#define MHOOK_JMPSIZE 5

//=========================================================================
// Toolhelp defintions so the functions can be dynamically bound to
typedef HANDLE (WINAPI * _CreateToolhelp32Snapshot)(
	DWORD dwFlags,       
	DWORD th32ProcessID  
	);

typedef BOOL (WINAPI * _Thread32First)(
									   HANDLE hSnapshot,     
									   LPTHREADENTRY32 lpte
									   );

typedef BOOL (WINAPI * _Thread32Next)(
									  HANDLE hSnapshot,     
									  LPTHREADENTRY32 lpte
									  );

//=========================================================================
// Bring in the toolhelp functions from kernel32
_CreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;//! = (_CreateToolhelp32Snapshot) GetProcAddress(GetModuleHandle(L"kernel32"), "CreateToolhelp32Snapshot");
_Thread32First fnThread32First;//! = (_Thread32First) GetProcAddress(GetModuleHandle(L"kernel32"), "Thread32First");
_Thread32Next fnThread32Next;//! = (_Thread32Next) GetProcAddress(GetModuleHandle(L"kernel32"), "Thread32Next");

//=========================================================================
static VOID EnterCritSec() {
	if (!g_bVarsInitialized) {
		InitializeCriticalSection(&g_cs);
		//ZeroMemory(g_pHooks, sizeof(g_pHooks));
		mem_set(g_pHooks, 0, sizeof(g_pHooks));
		g_bVarsInitialized = TRUE;
	}
	EnterCriticalSection(&g_cs);
}

//=========================================================================
static VOID LeaveCritSec() {
	LeaveCriticalSection(&g_cs);
}

//=========================================================================
// Internal function:
// 
// Skip over jumps that lead to the real function. Gets around import
// jump tables, etc.
//=========================================================================
static PBYTE SkipJumps(PBYTE pbCode) {
#ifdef _M_IX86_X64
	if (pbCode[0] == 0xff && pbCode[1] == 0x25) {
#ifdef _M_IX86
		// on x86 we have an absolute pointer...
		PBYTE pbTarget = *(PBYTE *)&pbCode[2];
		// ... that shows us an absolute pointer.
		return SkipJumps(*(PBYTE *)pbTarget);
#elif defined _M_X64
		// on x64 we have a 32-bit offset...
		INT32 lOffset = *(INT32 *)&pbCode[2];
		// ... that shows us an absolute pointer
		return SkipJumps(*(PBYTE*)(pbCode + 6 + lOffset));
#endif
	} else if (pbCode[0] == 0xe9) {
		// here the behavior is identical, we have...
		// ...a 32-bit offset to the destination.
		return SkipJumps(pbCode + 5 + *(INT32 *)&pbCode[1]);
	} else if (pbCode[0] == 0xeb) {
		// and finally an 8-bit offset to the destination
		return SkipJumps(pbCode + 2 + *(CHAR *)&pbCode[1]);
	}
#else
#error unsupported platform
#endif
	return pbCode;
}

//=========================================================================
// Internal function:
//
// Writes code at pbCode that jumps to pbJumpTo. Will attempt to do this
// in as few bytes as possible. Important on x64 where the long jump
// (0xff 0x25 ....) can take up 14 bytes.
//=========================================================================
static PBYTE EmitJump(PBYTE pbCode, PBYTE pbJumpTo) {
#ifdef _M_IX86_X64
	PBYTE pbJumpFrom = pbCode + 5;
	SIZE_T cbDiff = pbJumpFrom > pbJumpTo ? pbJumpFrom - pbJumpTo : pbJumpTo - pbJumpFrom;
	TRACE(L"mhooks: EmitJump: Jumping from %p to %p, diff is %p", pbJumpFrom, pbJumpTo, cbDiff);
	if (cbDiff <= 0x7fff0000) {
		pbCode[0] = 0xe9;
		pbCode += 1;
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbJumpTo - pbJumpFrom);
		pbCode += sizeof(DWORD);
	} else {
		pbCode[0] = 0xff;
		pbCode[1] = 0x25;
		pbCode += 2;
#ifdef _M_IX86
		// on x86 we write an absolute address (just behind the instruction)
		*((PDWORD)pbCode) = (DWORD)(DWORD_PTR)(pbCode + sizeof(DWORD));
#elif defined _M_X64
		// on x64 we write the relative address of the same location
		*((PDWORD)pbCode) = (DWORD)0;
#endif
		pbCode += sizeof(DWORD);
		*((PDWORD_PTR)pbCode) = (DWORD_PTR)(pbJumpTo);
		pbCode += sizeof(DWORD_PTR);
	}
#else 
#error unsupported platform
#endif
	return pbCode;
}

//=========================================================================
// Internal function:
//
// Will try to allocate the trampoline structure within 2 gigabytes of
// the target function. 
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineAlloc(PBYTE pSystemFunction, S64 nLimitUp, S64 nLimitDown) {

	MHOOKS_TRAMPOLINE* pTrampoline = NULL;

	// do we have room to store this guy?
	if (g_nHooksInUse < MHOOKS_MAX_SUPPORTED_HOOKS) {

		// determine lower and upper bounds for the allocation locations.
		// in the basic scenario this is +/- 2GB but IP-relative instructions
		// found in the original code may require a smaller window.
		PBYTE pLower = pSystemFunction + nLimitUp, pUpper = pSystemFunction + nLimitDown, pbAlloc;
		SYSTEM_INFO sSysInfo;
		mem_set(&sSysInfo, 0, sizeof(SYSTEM_INFO));

		pLower = pLower < (PBYTE)(DWORD_PTR)0x0000000080000000 ? 
							(PBYTE)(0x1) : (PBYTE)(pLower - (PBYTE)0x7fff0000);		
		pUpper = pUpper < (PBYTE)(DWORD_PTR)0xffffffff80000000 ? 
			(PBYTE)(pUpper + (DWORD_PTR)0x7ff80000) : (PBYTE)(DWORD_PTR)0xfffffffffff80000;
		DEBUG(L"mhooks: TrampolineAlloc: Allocating for %p between %p and %p", pSystemFunction, pLower, pUpper);

		GetSystemInfo(&sSysInfo);

		// go through the available memory blocks and try to allocate a chunk for us
		for (pbAlloc = pLower; pbAlloc < pUpper; ) {
			// determine current state
			MEMORY_BASIC_INFORMATION mbi;
			DEBUG(L"mhooks: TrampolineAlloc: Looking at address %p", pbAlloc);
			if (!VirtualQuery(pbAlloc, &mbi, sizeof(mbi)))
				break;
			// free & large enough?
			if (mbi.State == MEM_FREE && mbi.RegionSize >= sizeof(MHOOKS_TRAMPOLINE) && mbi.RegionSize >= sSysInfo.dwAllocationGranularity) {
				// yes, align the pointer to the 64K boundary first
				pbAlloc = (PBYTE)	(
										(ULONG_PTR) (
											((ULONG_PTR)pbAlloc + (sSysInfo.dwAllocationGranularity-1)) / 
											sSysInfo.dwAllocationGranularity
										) * sSysInfo.dwAllocationGranularity
									);
				// and then try to allocate it
				pTrampoline = (MHOOKS_TRAMPOLINE*)VirtualAlloc(pbAlloc, sizeof(MHOOKS_TRAMPOLINE), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READ);
				if (pTrampoline) {
					DEBUG(L"mhooks: TrampolineAlloc: Allocated block at %p as the trampoline", pTrampoline);
					break;
				}
			}
			// continue the search
			pbAlloc = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
		}

		// found and allocated a trampoline?
		if (pTrampoline) {
			// put it into our list so we know we'll have to free it
			DWORD i;
			for (i=0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
				if (g_pHooks[i] == NULL) {
					g_pHooks[i] = pTrampoline;
					g_nHooksInUse++;
					break;
				}
			}
		}
	}

	return pTrampoline;
}

//=========================================================================
// Internal function:
//
// Return the internal trampoline structure that belongs to a hooked function.
//=========================================================================
static MHOOKS_TRAMPOLINE* TrampolineGet(PBYTE pHookedFunction) {
	DWORD i;
	for (i=0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
		if (g_pHooks[i]) {
			if (g_pHooks[i]->codeTrampoline == pHookedFunction)
				return g_pHooks[i];
		}
	}
	return NULL;
}

//=========================================================================
// Internal function:
//
// Free a trampoline structure.
//=========================================================================
static VOID TrampolineFree(MHOOKS_TRAMPOLINE* pTrampoline, BOOL bNeverUsed) {
	DWORD i;
	for (i=0; i<MHOOKS_MAX_SUPPORTED_HOOKS; i++) {
		if (g_pHooks[i] == pTrampoline) {
			g_pHooks[i] = NULL;
			// It might be OK to call VirtualFree, but quite possibly it isn't: 
			// If a thread has some of our trampoline code on its stack
			// and we yank the region from underneath it then it will
			// surely crash upon returning. So instead of freeing the 
			// memory we just let it leak. Ugly, but safe.
			if (bNeverUsed)
				VirtualFree(pTrampoline, 0, MEM_RELEASE);
			g_nHooksInUse--;
			break;
		}
	}
}

BOOL _WaitForInstructionPointer(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);

	CONTEXT ctx;
	int nTries = 0;
	ctx.ContextFlags = CONTEXT_CONTROL;
	while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
		PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
		PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
		if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
			if (nTries < 100) {
				// oops - we should try to get the instruction pointer out of here. 
				TRACE(L"mhooks: WaitForInstructionPointer: thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp);
				//ResumeThread(hThread);
				Sleep(100);
				//SuspendThread(hThread);
				nTries++;
			} else {
				// we gave it all we could. (this will probably never 
				// happen - unless the thread has already been suspended 
				// to begin with)
				TRACE(L"mhooks: WaitForInstructionPointer: thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp);
				//ResumeThread(hThread);
				CloseHandle(hThread);
				hThread = NULL;
				//break;
				return FALSE;
			}
		} else {
			// success, the IP is not conflicting
			TRACE(L"mhooks: WaitForInstructionPointer: Successful - thread %d - IP is at %p", dwThreadId, pIp);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL WaitForInstructionPointer(PBYTE pbCode, DWORD cbBytes) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (!hSnap || hSnap==INVALID_HANDLE_VALUE) 
		return FALSE;
	{
		THREADENTRY32 te;
		BOOL success;
		te.dwSize = sizeof(te);
		
		if (Thread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {
					if (te.th32ThreadID != GetCurrentThreadId()) {
						if(!_WaitForInstructionPointer(te.th32ThreadID, pbCode, cbBytes)) {
							CloseHandle(hSnap);
							return FALSE;
						}
					}
				}
				te.dwSize = sizeof(te);
			} while(Thread32Next(hSnap, &te));
		}
	}
	CloseHandle(hSnap);
	return TRUE;
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//=========================================================================
static HANDLE SuspendOneThread(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
	// open the thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (GOOD_HANDLE(hThread)) {
		// attempt suspension
		DWORD dwSuspendCount = SuspendThread(hThread);
		if (dwSuspendCount != -1) {
			// see where the IP is
			CONTEXT ctx;
			int nTries = 0;
			ctx.ContextFlags = CONTEXT_CONTROL;
			while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
				if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
					if (nTries < 100) {
						// oops - we should try to get the instruction pointer out of here. 
						TRACE(L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp);
						ResumeThread(hThread);
						Sleep(100);
						SuspendThread(hThread);
						nTries++;
					} else {
						// we gave it all we could. (this will probably never 
						// happen - unless the thread has already been suspended 
						// to begin with)
						TRACE(L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp);
						ResumeThread(hThread);
						CloseHandle(hThread);
						hThread = NULL;
						break;
					}
				} else {
					// success, the IP is not conflicting
					TRACE(L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp);
					break;
				}
			}
		} else {
			// couldn't suspend
			CloseHandle(hThread);
			hThread = NULL;
		}
	}
	return hThread;
}

static HANDLE _SuspendOneThread(DWORD dwThreadId) {
	// open the thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (GOOD_HANDLE(hThread)) {
		// attempt suspension
		DWORD dwSuspendCount = SuspendThread(hThread);
		if (dwSuspendCount != -1) {
			// see where the IP is
			CONTEXT ctx;
			int nTries = 0;
			ctx.ContextFlags = CONTEXT_CONTROL;
			while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
				PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
				/*if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
					if (nTries < 100) {
						// oops - we should try to get the instruction pointer out of here. 
						TRACE(L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp);
						ResumeThread(hThread);
						Sleep(100);
						SuspendThread(hThread);
						nTries++;
					} else {
						// we gave it all we could. (this will probably never 
						// happen - unless the thread has already been suspended 
						// to begin with)
						TRACE(L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp);
						ResumeThread(hThread);
						CloseHandle(hThread);
						hThread = NULL;
						break;
					}
				} else*/ {
					// success, the IP is not conflicting
					TRACE(L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp);
					break;
				}
			}
		} else {
			// couldn't suspend
			CloseHandle(hThread);
			hThread = NULL;
		}
	}
	return hThread;
}

//=========================================================================
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//=========================================================================
static VOID ResumeOtherThreads() {
	// make sure things go as fast as possible
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	HANDLE hSnap;
	THREADENTRY32 te;
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);	
	hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	// go through our list
	//for (DWORD i=0; i<g_nThreadHandles; i++) {
	te.dwSize = sizeof(te);
	if (fnThread32First(hSnap, &te)) do {
		HANDLE hThread;
		if(te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId()) 
			continue;
		TRACE(L"resuming %d...", te.th32ThreadID);
		// and resume & close thread handles
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
		ResumeThread(hThread);
		CloseHandle(hThread);
		TRACE(L"done");
		//te.dwSize = sizeof(te);
	} while(fnThread32Next(hSnap, &te));
	CloseHandle(hSnap);
	// clean up
	//free(g_hThreadHandles);
	//g_hThreadHandles = NULL;
	//g_nThreadHandles = 0;
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
}

//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their 
// instruction pointer is not in the given range.
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
	BOOL bRet = FALSE;
	// make sure we're the most important thread in the process
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	HANDLE hSnap ;
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// get a view of the threads in the system
	hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (GOOD_HANDLE(hSnap)) {
		DWORD nThreadsInProcess = 0;
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		// count threads in this process (except for ourselves)		
		if (fnThread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {
					if (te.th32ThreadID != GetCurrentThreadId()) {
						nThreadsInProcess++;
					}
				}
				te.dwSize = sizeof(te);
			} while(fnThread32Next(hSnap, &te));
		}
		TRACE(L"mhooks: SuspendOtherThreads: counted %d other threads", nThreadsInProcess);
		if (nThreadsInProcess) {
			// alloc buffer for the handles we really suspended
			g_hThreadHandles = (HANDLE*)mem_alloc(nThreadsInProcess*sizeof(HANDLE));
			if (g_hThreadHandles) {
				DWORD nCurrentThread = 0;
				BOOL bFailed = FALSE;
				//ZeroMemory(g_hThreadHandles, nThreadsInProcess*sizeof(HANDLE));				
				mem_set(g_hThreadHandles, 0, nThreadsInProcess*sizeof(HANDLE));
				te.dwSize = sizeof(te);
				// go through every thread
				if (fnThread32First(hSnap, &te)) {
					do {
						if (te.th32OwnerProcessID == GetCurrentProcessId()) {
							if (te.th32ThreadID != GetCurrentThreadId()) {
								// attempt to suspend it
								g_hThreadHandles[nCurrentThread] = SuspendOneThread(te.th32ThreadID, pbCode, cbBytes);
								if (GOOD_HANDLE(g_hThreadHandles[nCurrentThread])) {
									TRACE(L"mhooks: SuspendOtherThreads: successfully suspended %d", te.th32ThreadID);
									nCurrentThread++;
								} else {
									TRACE(L"mhooks: SuspendOtherThreads: error while suspending thread %d: %d", te.th32ThreadID, gle());
									// TODO: this might not be the wisest choice
									// but we can choose to ignore failures on
									// thread suspension. It's pretty unlikely that
									// we'll fail - and even if we do, the chances
									// of a thread's IP being in the wrong place
									// is pretty small.
									// bFailed = TRUE;
								}
							}
						}
						te.dwSize = sizeof(te);
					} while(fnThread32Next(hSnap, &te) && !bFailed);
				}
				g_nThreadHandles = nCurrentThread;
				bRet = !bFailed;
			}
		}
		CloseHandle(hSnap);
		//TODO: we might want to have another pass to make sure all threads
		// in the current process (including those that might have been
		// created since we took the original snapshot) have been 
		// suspended.
	} else {
		TRACE(L"mhooks: SuspendOtherThreads: can't CreateToolhelp32Snapshot: %d", gle());
	}
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
	if (!bRet) {
		TRACE(L"mhooks: SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads.");
		ResumeOtherThreads();
	}
	return bRet;
}

static BOOL _SuspendOtherThreads() {
	BOOL bRet = FALSE;
	HANDLE hSnap;
	// make sure we're the most important thread in the process
	INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	// get a view of the threads in the system
	hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (GOOD_HANDLE(hSnap)) {
		THREADENTRY32 te;
		DWORD nThreadsInProcess = 0;
		te.dwSize = sizeof(te);
		// count threads in this process (except for ourselves)		
		if (fnThread32First(hSnap, &te)) {
			do {
				if (te.th32OwnerProcessID == GetCurrentProcessId()) {
					if (te.th32ThreadID != GetCurrentThreadId()) {
						nThreadsInProcess++;
					}
				}
				te.dwSize = sizeof(te);
			} while(fnThread32Next(hSnap, &te));
		}
		TRACE(L"mhooks: SuspendOtherThreads: counted %d other threads", nThreadsInProcess);
		if (nThreadsInProcess) {
			// alloc buffer for the handles we really suspended
			//g_hThreadHandles = (HANDLE*)mem_alloc(nThreadsInProcess*sizeof(HANDLE));
			//if (g_hThreadHandles) 
			{
				//ZeroMemory(g_hThreadHandles, nThreadsInProcess*sizeof(HANDLE));
				DWORD nCurrentThread = 0;
				BOOL bFailed = FALSE;
				te.dwSize = sizeof(te);
				// go through every thread
				if (fnThread32First(hSnap, &te)) {
					do {
						if (te.th32OwnerProcessID == GetCurrentProcessId()) {
							if (te.th32ThreadID != GetCurrentThreadId()) {
								// attempt to suspend it
								HANDLE h=_SuspendOneThread(te.th32ThreadID);
								if (GOOD_HANDLE(h)) {
									TRACE(L"mhooks: SuspendOtherThreads: successfully suspended %d", te.th32ThreadID);
									nCurrentThread++;
								} else {
									TRACE(L"mhooks: SuspendOtherThreads: error while suspending thread %d: %d", te.th32ThreadID, gle());
									// TODO: this might not be the wisest choice
									// but we can choose to ignore failures on
									// thread suspension. It's pretty unlikely that
									// we'll fail - and even if we do, the chances
									// of a thread's IP being in the wrong place
									// is pretty small.
									// bFailed = TRUE;
								}
							}
						}
						te.dwSize = sizeof(te);
					} while(fnThread32Next(hSnap, &te) && !bFailed);
				}
				g_nThreadHandles = nCurrentThread;
				bRet = !bFailed;
			}
		}
		CloseHandle(hSnap);
		//TODO: we might want to have another pass to make sure all threads
		// in the current process (including those that might have been
		// created since we took the original snapshot) have been 
		// suspended.
	} else {
		TRACE(L"mhooks: SuspendOtherThreads: can't CreateToolhelp32Snapshot: %d", gle());
	}
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
	if (!bRet) {
		TRACE(L"mhooks: SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads.");
		ResumeOtherThreads();
	}
	return bRet;
}

//=========================================================================
// if IP-relative addressing has been detected, fix up the code so the
// offset points to the original location
static void FixupIPRelativeAddressing(PBYTE pbNew, PBYTE pbOriginal, MHOOKS_PATCHDATA* pdata)
{
#if defined _M_X64
	S64 diff = pbNew - pbOriginal;
	DWORD i;
	for (i = 0; i < pdata->nRipCnt; i++) {
		DWORD dwNewDisplacement = (DWORD)(pdata->rips[i].nDisplacement - diff);
		TRACE(L"mhooks: fixing up RIP instruction operand for code at 0x%p: "
			L"old displacement: 0x%8.8x, new displacement: 0x%8.8x", 
			pbNew + pdata->rips[i].dwOffset, 
			(DWORD)pdata->rips[i].nDisplacement, 
			dwNewDisplacement);
		*(PDWORD)(pbNew + pdata->rips[i].dwOffset) = dwNewDisplacement;
	}
#endif
}

//=========================================================================
// Examine the machine code at the target function's entry point, and
// skip bytes in a way that we'll always end on an instruction boundary.
// We also detect branches and subroutine calls (as well as returns)
// at which point disassembly must stop.
// Finally, detect and collect information on IP-relative instructions
// that we can patch.
static DWORD DisassembleAndSkip(PVOID pFunction, DWORD dwMinLen, MHOOKS_PATCHDATA* pdata) {
#ifdef _M_IX86
	ARCHITECTURE_TYPE arch = ARCH_X86;
#elif defined _M_X64
	ARCHITECTURE_TYPE arch = ARCH_X64;
#else
#error unsupported platform
#endif
	DWORD dwRet = 0, i;
	DISASSEMBLER dis;
	pdata->nLimitDown = 0;
	pdata->nLimitUp = 0;
	pdata->nRipCnt = 0;	
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL; 
		U8* pLoc = (U8*)pFunction;
		DWORD dwFlags = DISASM_DECODE | DISASM_DISASSEMBLE | DISASM_ALIGNOUTPUT;

		TRACE(L"mhooks: DisassembleAndSkip: Disassembling %p", pLoc);
		while ( (dwRet < dwMinLen) && (pins = GetInstruction(&dis, (ULONG_PTR)pLoc, pLoc, dwFlags)) ) {
			BOOL bProcessRip = FALSE;
#ifdef _TRACE_DISASM
			TRACE(L"mhooks: DisassembleAndSkip: %p: %hs", pLoc, pins->String);
#else
			DEBUG(L"mhooks: DisassembleAndSkip: %p", pLoc);
#endif // _TRACE_DISASM
			if (pins->Type == ITYPE_RET		) break;
			if (pins->Type == ITYPE_BRANCH	) break;
			if (pins->Type == ITYPE_BRANCHCC) break;
			if (pins->Type == ITYPE_CALL	) break;
			if (pins->Type == ITYPE_CALLCC	) break;

			#if defined _M_X64				
				// mov or lea to register from rip+imm32
				if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[1].Flags & OP_IPREL) && (pins->Operands[1].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov reg, [rip+imm32]"
					DEBUG(L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 1, pins->X86.Displacement, *(PDWORD)(pLoc+3));
					bProcessRip = TRUE;
				}
				// mov or lea to rip+imm32 from register
				else if ((pins->Type == ITYPE_MOV || pins->Type == ITYPE_LEA) && (pins->X86.Relative) && 
					(pins->X86.OperandSize == 8) && (pins->OperandCount == 2) &&
					(pins->Operands[0].Flags & OP_IPREL) && (pins->Operands[0].Register == AMD64_REG_RIP))
				{
					// rip-addressing "mov [rip+imm32], reg"
					DEBUG(L"mhooks: DisassembleAndSkip: found OP_IPREL on operand %d with displacement 0x%x (in memory: 0x%x)", 0, pins->X86.Displacement, *(PDWORD)(pLoc+3));
					bProcessRip = TRUE;
				}
				else if ( (pins->OperandCount >= 1) && (pins->Operands[0].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					DEBUG(L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 0);
					// dump instruction bytes to the debug output
					for (i=0; i<pins->Length; i++) {
						DEBUG(L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]);
					}
					break;
				}
				else if ( (pins->OperandCount >= 2) && (pins->Operands[1].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					DEBUG(L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 1);
					// dump instruction bytes to the debug output
					for (i=0; i<pins->Length; i++) {
						DEBUG(L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]);
					}
					break;
				}
				else if ( (pins->OperandCount >= 3) && (pins->Operands[2].Flags & OP_IPREL) )
				{
					// unsupported rip-addressing
					DEBUG(L"mhooks: DisassembleAndSkip: found unsupported OP_IPREL on operand %d", 2);
					// dump instruction bytes to the debug output
					for (i=0; i<pins->Length; i++) {
						DEBUG(L"mhooks: DisassembleAndSkip: instr byte %2.2d: 0x%2.2x", i, pLoc[i]);
					}
					break;
				}
				// follow through with RIP-processing if needed
				if (bProcessRip) {
					// calculate displacement relative to function start
					S64 nAdjustedDisplacement = pins->X86.Displacement + (pLoc - (U8*)pFunction);
					// store displacement values furthest from zero (both positive and negative)
					if (nAdjustedDisplacement < pdata->nLimitDown)
						pdata->nLimitDown = nAdjustedDisplacement;
					if (nAdjustedDisplacement > pdata->nLimitUp)
						pdata->nLimitUp = nAdjustedDisplacement;
					// store patch info
					if (pdata->nRipCnt < MHOOKS_MAX_RIPS) {
						pdata->rips[pdata->nRipCnt].dwOffset = dwRet + 3;
						pdata->rips[pdata->nRipCnt].nDisplacement = pins->X86.Displacement;
						pdata->nRipCnt++;
					} else {
						// no room for patch info, stop disassembly
						break;
					}
				}
			#endif

			dwRet += pins->Length;
			pLoc  += pins->Length;
		}

		CloseDisassembler(&dis);
	}

	return dwRet;
}
INT nOriginalPriority;
BOOL Mhook_begin() {
	EnterCritSec();	
	nOriginalPriority = GetThreadPriority(GetCurrentThread());
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	//_SuspendOtherThreads();	
	return TRUE;
}

BOOL Mhook_end() { 
	//ResumeOtherThreads();	
	SetThreadPriority(GetCurrentThread(), nOriginalPriority);
	LeaveCritSec(); 	
	TRACE(L"Done!");
	return TRUE;
}

BOOL Mhook_hook(PVOID *ppSystemFunction, PVOID pHookFunction) {
	MHOOKS_TRAMPOLINE* pTrampoline = NULL;
	PVOID pSystemFunction = *ppSystemFunction;	
	MHOOKS_PATCHDATA patchdata;	
	DWORD dwInstructionLength ;
	
	mem_set(&patchdata, 0, sizeof(patchdata));
	TRACE(L"mhooks: Mhook_SetHook: Started on the job: %p / %p", pSystemFunction, pHookFunction);
	// find the real functions (jump over jump tables, if any)
	pSystemFunction = SkipJumps((PBYTE)pSystemFunction);
	pHookFunction   = SkipJumps((PBYTE)pHookFunction);
	TRACE(L"mhooks: Mhook_hook: Started on the job: %p / %p", pSystemFunction, pHookFunction);
	// figure out the length of the overwrite zone
	dwInstructionLength = DisassembleAndSkip(pSystemFunction, MHOOK_JMPSIZE, &patchdata);
	if (dwInstructionLength >= MHOOK_JMPSIZE) {
		TRACE(L"mhooks: Mhook_SetHook: disassembly signals %d bytes", dwInstructionLength);
		/*if(!WaitForInstructionPointer((PBYTE)pSystemFunction, dwInstructionLength)) {
			TRACE(L"mhooks: Mhook_hook: could not get IP out of the way");
			return FALSE;
		}*/

		// allocate a trampoline structure (TODO: it is pretty wasteful to get
		// VirtualAlloc to grab chunks of memory smaller than 100 bytes)
		pTrampoline = TrampolineAlloc((PBYTE)pSystemFunction, patchdata.nLimitUp, patchdata.nLimitDown);
		if (pTrampoline) {
			HANDLE hProc = GetCurrentProcess();
			DWORD dwOldProtectSystemFunction = 0;
			DWORD dwOldProtectTrampolineFunction = 0;
			DEBUG(L"mhooks: Mhook_SetHook: allocated structure at %p", pTrampoline);

			// set the system function to PAGE_EXECUTE_READWRITE
			if (VirtualProtectEx(hProc, pSystemFunction, dwInstructionLength, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
				DEBUG(L"mhooks: Mhook_SetHook: readwrite set on system function");
				// mark our trampoline buffer to PAGE_EXECUTE_READWRITE
				if (VirtualProtectEx(hProc, pTrampoline, sizeof(MHOOKS_TRAMPOLINE), PAGE_EXECUTE_READWRITE, &dwOldProtectTrampolineFunction)) {
					PBYTE pbCode;
					DWORD_PTR dwDistance, i;
					DEBUG(L"mhooks: Mhook_SetHook: readwrite set on trampoline structure");

					// create our trampoline function
					pbCode = pTrampoline->codeTrampoline;
					// save original code..
					for (i = 0; i<dwInstructionLength; i++) {
						pTrampoline->codeUntouched[i] = pbCode[i] = ((PBYTE)pSystemFunction)[i];
					}
					pbCode += dwInstructionLength;
					// plus a jump to the continuation in the original location
					pbCode = EmitJump(pbCode, ((PBYTE)pSystemFunction) + dwInstructionLength);
					DEBUG(L"mhooks: Mhook_SetHook: updated the trampoline");

					// fix up any IP-relative addressing in the code
					FixupIPRelativeAddressing(pTrampoline->codeTrampoline, (PBYTE)pSystemFunction, &patchdata);

					dwDistance = (PBYTE)pHookFunction < (PBYTE)pSystemFunction ? 
						(PBYTE)pSystemFunction - (PBYTE)pHookFunction : (PBYTE)pHookFunction - (PBYTE)pSystemFunction;
					if (dwDistance > 0x7fff0000) {
						// create a stub that jumps to the replacement function.
						// we need this because jumping from the API to the hook directly 
						// will be a long jump, which is 14 bytes on x64, and we want to 
						// avoid that - the API may or may not have room for such stuff. 
						// (remember, we only have 5 bytes guaranteed in the API.)
						// on the other hand we do have room, and the trampoline will always be
						// within +/- 2GB of the API, so we do the long jump in there. 
						// the API will jump to the "reverse trampoline" which
						// will jump to the user's hook code.
						pbCode = pTrampoline->codeJumpToHookFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
						TRACE(L"mhooks: Mhook_SetHook: created reverse trampoline");
						FlushInstructionCache(hProc, pTrampoline->codeJumpToHookFunction, 
							pbCode - pTrampoline->codeJumpToHookFunction);

						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, pTrampoline->codeJumpToHookFunction);
					} else {
						// the jump will be at most 5 bytes so we can do it directly
						// update the API itself
						pbCode = (PBYTE)pSystemFunction;
						pbCode = EmitJump(pbCode, (PBYTE)pHookFunction);
					}

					// update data members
					pTrampoline->cbOverwrittenCode = dwInstructionLength;
					pTrampoline->pSystemFunction = (PBYTE)pSystemFunction;
					pTrampoline->pHookFunction = (PBYTE)pHookFunction;

					// flush instruction cache and restore original protection
					FlushInstructionCache(hProc, pTrampoline->codeTrampoline, dwInstructionLength);
					VirtualProtectEx(hProc, pTrampoline, sizeof(MHOOKS_TRAMPOLINE), dwOldProtectTrampolineFunction, &dwOldProtectTrampolineFunction);
				} else {
					TRACE(L"mhooks: Mhook_SetHook: failed VirtualProtectEx 2: %d", gle());
				}
				// flush instruction cache and restore original protection
				FlushInstructionCache(hProc, pSystemFunction, dwInstructionLength);
				VirtualProtectEx(hProc, pSystemFunction, dwInstructionLength, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			} else {
				TRACE(L"mhooks: Mhook_SetHook: failed VirtualProtectEx 1: %d", gle());
			}
			if (pTrampoline->pSystemFunction) {
				// this is what the application will use as the entry point
				// to the "original" unhooked function.
				*ppSystemFunction = pTrampoline->codeTrampoline;
				TRACE(L"mhooks: Mhook_SetHook: Hooked the function!");
			} else {
				// if we failed discard the trampoline (forcing VirtualFree)
				TrampolineFree(pTrampoline, TRUE);
				pTrampoline = NULL;
			}
		}		
	} else {
		TRACE(L"mhooks: disassembly signals %d bytes (unacceptable)", dwInstructionLength);
	}	
	return (pTrampoline != NULL);
}

//=========================================================================
extern void* current_hook;

BOOL Mhook_unhook(PVOID *ppHookedFunction) {
	BOOL bRet = FALSE;	
	MHOOKS_TRAMPOLINE* pTrampoline = TrampolineGet((PBYTE)*ppHookedFunction);
	TRACE(L"mhooks: Mhook_Unhook: %p", *ppHookedFunction);

	// get the trampoline structure that corresponds to our function	
	if (pTrampoline) {
		HANDLE hProc = GetCurrentProcess();
		DWORD dwOldProtectSystemFunction = 0;
		int nTries = 0;		
		TRACE(L"mhooks: Mhook_Unhook: found struct at %p", pTrampoline);
		while(current_hook == *ppHookedFunction || current_hook == pTrampoline->pSystemFunction || current_hook == pTrampoline->pHookFunction) {
			int _err, _res;
			//_res = orig_WSPCancelBlockingCall(&_err);
			if(nTries%10==0)
				TRACE(L"mhooks: Mhook_Unhook: waiting for the function to exit...");
			Sleep(10);
			//if(nTries-- < 0) return FALSE;
		}
		/*if(!WaitForInstructionPointer(pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode) ||
			!WaitForInstructionPointer(*ppHookedFunction, pTrampoline->cbOverwrittenCode)) {
			TRACE(L"mhooks: Mhook_unhook: could not get IP out of the way");
			return FALSE;
		}*/ 
		//RaiseException(CONTROL_C_EXIT, 0, 0, NULL);
		
		// make memory writable
		if (VirtualProtectEx(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, PAGE_EXECUTE_READWRITE, &dwOldProtectSystemFunction)) {
			PBYTE pbCode = (PBYTE)pTrampoline->pSystemFunction;
			DWORD i;
			//! TRACE(L"mhooks: Mhook_Unhook: readwrite set on system function");
			for (i = 0; i<pTrampoline->cbOverwrittenCode; i++) {
				pbCode[i] = pTrampoline->codeUntouched[i];
			}
			// flush instruction cache and make memory unwritable
			FlushInstructionCache(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode);
			VirtualProtectEx(hProc, pTrampoline->pSystemFunction, pTrampoline->cbOverwrittenCode, dwOldProtectSystemFunction, &dwOldProtectSystemFunction);
			// return the original function pointer
			*ppHookedFunction = pTrampoline->pSystemFunction;
			bRet = TRUE;
			TRACE(L"mhooks: Mhook_Unhook: sysfunc: %p", *ppHookedFunction);
			// free the trampoline while not really discarding it from memory
			TrampolineFree(pTrampoline, FALSE);
			TRACE(L"mhooks: Mhook_Unhook: unhook successful");
		} else {
			TRACE(L"mhooks: Mhook_Unhook: failed VirtualProtectEx 1: %d", gle());
		}		
	}	
	return bRet;
}
