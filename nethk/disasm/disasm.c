/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	disasm.c
 * purpose:		x86 multi-platform disassembler interface
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

#include "mincrt/mincrt.h"
#include <windows.h>
#include "disasm.h"

#ifdef NO_SANITY_CHECKS
#undef assert
#define assert(x)
#endif

//////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////

ARCHITECTURE_FORMAT SupportedArchitectures[] =
{
	{ ARCH_X86,	&X86 },
	{ ARCH_X86_16, &X86 },
	{ ARCH_X64,	&X86 },
	{ ARCH_UNKNOWN, NULL }
};

typedef struct _DISASM_ARG_INFO
{
	INSTRUCTION *MatchedInstruction;
	BOOL MatchPrefix;
	U8 *Opcode;
	U32 OpcodeLength;
	INSTRUCTION_TYPE InstructionType;
	U32 Count;
} DISASM_ARG_INFO;

//////////////////////////////////////////////////////////////////////
// Function prototypes
//////////////////////////////////////////////////////////////////////

BOOL InitInstruction(INSTRUCTION *Instruction, DISASSEMBLER *Disassembler);
struct _ARCHITECTURE_FORMAT *GetArchitectureFormat(ARCHITECTURE_TYPE Type);

//////////////////////////////////////////////////////////////////////
// Disassembler setup
//////////////////////////////////////////////////////////////////////

BOOL InitDisassembler(DISASSEMBLER *Disassembler, ARCHITECTURE_TYPE Architecture)
{
	ARCHITECTURE_FORMAT *ArchFormat;

	mem_set(Disassembler, 0, sizeof(DISASSEMBLER));
	Disassembler->Initialized = DISASSEMBLER_INITIALIZED;
	
	ArchFormat = GetArchitectureFormat(Architecture);
	if (!ArchFormat) { assert(0); return FALSE; }
	Disassembler->ArchType = ArchFormat->Type;
	Disassembler->Functions = ArchFormat->Functions;
	return TRUE;
}

void CloseDisassembler(DISASSEMBLER *Disassembler)
{
	mem_set(Disassembler, 0, sizeof(DISASSEMBLER));
}

//////////////////////////////////////////////////////////////////////
// Instruction setup
//////////////////////////////////////////////////////////////////////

BOOL InitInstruction(INSTRUCTION *Instruction, DISASSEMBLER *Disassembler)
{
	mem_set(Instruction, 0, sizeof(INSTRUCTION));
	Instruction->Initialized = INSTRUCTION_INITIALIZED;
	Instruction->Disassembler = Disassembler;
#ifdef _TRACE_DISASM
	mem_set(Instruction->String, ' ', MAX_OPCODE_DESCRIPTION-1);
	Instruction->String[MAX_OPCODE_DESCRIPTION-1] = '\0';
#endif
	return TRUE;
}

// If Decode = FALSE, only the following fields are valid:
// Instruction->Length, Instruction->Address, Instruction->Prefixes, Instruction->PrefixCount,
// Instruction->OpcodeBytes, Instruction->Instruction->OpcodeLength, Instruction->Groups,
// Instruction->Type, Instruction->OperandCount
//
// If Disassemble = TRUE, then Instruction->String is valid (also requires Decode = TRUE)
//
// WARNING: This will overwrite the previously obtained instruction
INSTRUCTION *GetInstruction(DISASSEMBLER *Disassembler, U64 VirtualAddress, U8 *Address, U32 Flags)
{
	if (Disassembler->Initialized != DISASSEMBLER_INITIALIZED) { assert(0); return NULL; }
	assert(Address);
	InitInstruction(&Disassembler->Instruction, Disassembler);
	Disassembler->Instruction.Address = Address;	
	Disassembler->Instruction.VirtualAddressDelta = VirtualAddress - (U64)Address;
	if (!Disassembler->Functions->GetInstruction(&Disassembler->Instruction, Address, Flags))
	{
		assert(Disassembler->Instruction.Address == Address);
		assert(Disassembler->Instruction.Length < MAX_INSTRUCTION_LENGTH);

		// Save the address that failed, in case the lower-level disassembler didn't
		Disassembler->Instruction.Address = Address;
		Disassembler->Instruction.ErrorOccurred = TRUE;
		return NULL;
	}
	return &Disassembler->Instruction;
}

///////////////////////////////////////////////////////////////////////////
// Miscellaneous
///////////////////////////////////////////////////////////////////////////

static ARCHITECTURE_FORMAT *GetArchitectureFormat(ARCHITECTURE_TYPE Type)
{
	ARCHITECTURE_FORMAT *Format;
	for (Format = SupportedArchitectures; Format->Type != ARCH_UNKNOWN; Format++)
	{
		if (Format->Type == Type) return Format;
	}

	assert(0);
	return NULL;
}

