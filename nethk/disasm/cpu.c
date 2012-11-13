/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	cpu.c
 * purpose:		helper functions for disasm
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

#include "cpu.h"
#ifdef _DEBUG_MHOOK
	#include <assert.h>
#else
#define assert(a)
#endif

// NOTE: this assumes default scenarios (i.e., we assume CS/DS/ES/SS and flat
// and all have a base of 0 and limit of 0xffffffff, we don't try to verify
// that in the GDT)
//
// TODO: use inline assembly to get selector for segment
// Segment = x86 segment register (SEG_ES = 0, SEG_CS = 1, ...)
BYTE *GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset)
{
	switch (Segment)
	{
		// Windows uses a flat address space (except FS for x86 and GS for x64)
		case 0: // SEG_ES
		case 1: // SEG_CS
		case 2: // SEG_SS
		case 3: // SEG_DS
			return (BYTE *)(DWORD_PTR)Offset;
		case 4: // SEG_FS
		case 5: // SEG_GS
			return (BYTE *)(DWORD_PTR)Offset;
			// Note: we're really supposed to do this, but get_teb is not implemented
			// in this bastardized version of the disassembler.
			// return (BYTE *)get_teb() + Offset;
		default:
			assert(0);
			return (BYTE *)(DWORD_PTR)Offset;
	}
}

// This is an GDT/LDT selector (pGDT+Selector)
BYTE *GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset)
{
	DESCRIPTOR_ENTRY Entry;
	GATE_ENTRY *Gate;
	ULONG_PTR Base;
	
	assert(Selector < 0x10000);
	if (!GetThreadSelectorEntry(GetCurrentThread(), Selector, (LDT_ENTRY *)&Entry)) return NULL;
	if (!Entry.Present) return NULL;
	if (Entry.System)
	{
		Base = 0;
#ifdef _WIN64
		Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
		Base |= Entry.BaseHi << 24;
		Base |= Entry.BaseMid << 16;
		Base |= Entry.BaseLow;
	}
	else
	{
		switch (Entry.Type)
		{
			case 1: // 16-bit TSS (available)
			case 2: // LDT
			case 3: // 16-bit TSS (busy)
			case 9: // 32-bit TSS (available)
			case 11: // 32-bit TSS (busy)
				Base = 0;
#ifdef _WIN64
				Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
				Base |= Entry.BaseHi << 24;
				Base |= Entry.BaseMid << 16;
				Base |= Entry.BaseLow;
				break;

			case 4: // 16-bit call gate
			case 5: // task gate
			case 6: // 16-bit interrupt gate
			case 7: // 16-bit task gate
			case 12: // 32-bit call gate
			case 14: // 32-bit interrupt gate
			case 15: // 32-bit trap gate
				Gate = (GATE_ENTRY *)&Entry;
#ifdef _WIN64
				Base = ((ULONG_PTR)Gate->HighOffset64 << 32) | (Gate->HighOffset << 16) | Gate->LowOffset;
#else
				Base = (Gate->HighOffset << 16) | Gate->LowOffset;
#endif
				assert(!Offset); Offset = 0;
				break;
			default:
				assert(0);
				return NULL;
		}
	}
	return (BYTE *)Base + Offset;
}

