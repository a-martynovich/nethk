/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	handlers.c
 * purpose:		runtime-hooking of WSP* functions
 */

#include <stdint.h>
#include <ws2spi.h>
#include "mhook/mhook.h"
#include "mincrt/mincrt.h"
#include "nethk.h"

#ifdef _M_X64
#define CODE_MODE	X86IM_IO_MODE_64BIT
#else
#define CODE_MODE	X86IM_IO_MODE_32BIT
#endif

static LPWSPPROC_TABLE _find_sockproctable_simple() {
	HMODULE hMswsock=LoadLibrary(L"mswsock.dll");
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pDataSection, pCodeSection;
	LPWSPPROC_TABLE SockProcTable;
	DWORD	i, c=0;	
	UINT_PTR addr;

	if(!hMswsock)
		return 0;

	pDosHeader=(PIMAGE_DOS_HEADER)hMswsock;
	pNtHeaders=(PIMAGE_NT_HEADERS)((PBYTE)pDosHeader->e_lfanew + (UINT_PTR)pDosHeader);

	// The code ('.text') section is always first
	pCodeSection = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders+sizeof(IMAGE_NT_HEADERS));
	// We also need to find '.data' section. It could be 3rd or 4th. 
	for(i=1; i<pNtHeaders->FileHeader.NumberOfSections; i++) {
		pDataSection=(PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders
			+sizeof(IMAGE_NT_HEADERS) + 
			i*sizeof(IMAGE_SECTION_HEADER));	
		if(!strcmp(pDataSection->Name, ".data"))
			break;
		else pDataSection = 0;
	}
	if(!pDataSection) {
		_error_message(L"find_sockproctable_simple(): cannot find .data section!");
		DebugBreak();
	}

	for(i = 0; i<pDataSection->Misc.VirtualSize; i+=sizeof(UINT_PTR)) {
		addr = *((PUINT_PTR)((PBYTE)hMswsock+pDataSection->VirtualAddress+i));
		if((LPVOID)addr > pCodeSection && (LPVOID)addr < pCodeSection+(UINT_PTR)pCodeSection->Misc.VirtualSize) {
			c++;
		} else c=0;
		if(c==30) {
			SockProcTable = (LPWSPPROC_TABLE)((PBYTE)hMswsock+pDataSection->VirtualAddress+i-29*sizeof(UINT_PTR));
			break;
		}
	}
	return SockProcTable;
}
#include "disasm/disasm.h"
#ifdef _M_X64

static LPWSPPROC_TABLE _find_sockproctable(const void* p_WSPStartup) {
	LPWSPPROC_TABLE		tmp_result;
	LPWSPPROC_TABLE		result = 0;
	size_t				curr_pos = 0;

	ARCHITECTURE_TYPE arch = ARCH_X64;
	DWORD dwRet = 0;
	DISASSEMBLER dis;
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL; 
		DWORD dwFlags = DISASM_DECODE;
		U8* pLoc = (U8*)p_WSPStartup;		
		for(curr_pos = 0; curr_pos < 0x300; curr_pos += pins->Length) {			

			// look for "lea rdx, [offset]"
			pins = GetInstruction(&dis, (ULONG_PTR)(pLoc+curr_pos), (pLoc+curr_pos), dwFlags);
			if(pins->Type != ITYPE_LEA || pins->Operands[0].Register != AMD64_REG_RDX)
				continue;
			tmp_result = (LPWSPPROC_TABLE) (
				(char*)p_WSPStartup + curr_pos + pins->X86.Displacement + pins->Length 
				);
			curr_pos += pins->Length;

			// check "mov r8d, 0xf0"			
			pins = GetInstruction(&dis, (ULONG_PTR)(pLoc+curr_pos), (pLoc+curr_pos), dwFlags);			
			if(!pins) 
				break;
			if(pins->Type != ITYPE_MOV ||
				pins->Operands[1].Type != OPTYPE_IMM ||
				pins->Operands[1].Value_U64 !=0xf0) 
				continue;
			result = tmp_result;
			break;
		}
		CloseDisassembler(&dis);
	}
	return result;
}

#else

static LPWSPPROC_TABLE _find_sockproctable(const void* p_WSPStartup) {
	LPWSPPROC_TABLE		tmp_result;
	LPWSPPROC_TABLE		result = 0;
	size_t				curr_pos = 0, new_curr_pos, i;

	ARCHITECTURE_TYPE arch = ARCH_X86;
	DWORD dwRet = 0;
	DISASSEMBLER dis;
	if (InitDisassembler(&dis, arch)) {
		INSTRUCTION* pins = NULL; 
		DWORD dwFlags = DISASM_DECODE;
		U8* pLoc = (U8*)p_WSPStartup;		
		for(curr_pos = 0; curr_pos < 0x300; curr_pos += pins->Length) {			

			// look for "mov esi, offset"
			pins = GetInstruction(&dis, (ULONG_PTR)(pLoc+curr_pos), (pLoc+curr_pos), dwFlags);
			if(!pins) break;
			if(pins->Type != ITYPE_MOV || 
				pins->Operands[0].Register != X86_REG_ESI || 
				pins->Operands[1].Type != OPTYPE_IMM)
				continue;
			tmp_result = (LPWSPPROC_TABLE)pins->Operands[1].Value_U64;

			new_curr_pos = curr_pos;
			for(i=0; i<3; i++) {
				new_curr_pos += pins->Length;

				// check "rep movsd [edi], [esi]"
				pins = GetInstruction(&dis, (ULONG_PTR)(pLoc+new_curr_pos), (pLoc+new_curr_pos), dwFlags);
				if(!pins) 
					break;
				if(!pins->Repeat ||
					pins->Type != ITYPE_STRMOV)
					continue;

				result = tmp_result;
				break;
			}
			if(result)
				break;
		}
		CloseDisassembler(&dis);
	}
	return result;
}

#endif

/*
 * see nethk.h for description
 */
LPWSPPROC_TABLE get_sockproctable()
{
	HMODULE			h_mswsock;
	LPWSPPROC_TABLE	result = 0, result1 = 0;

	h_mswsock = LoadLibrary(TEXT("mswsock.dll"));

	if (h_mswsock)
	{
		/*void* p_WSPStartup = GetProcAddress(h_mswsock, "WSPStartup");

		if (p_WSPStartup) {			
			result = _find_sockproctable(p_WSPStartup);
		}*/
		result = _find_sockproctable_simple();
	}

	return result;
}
