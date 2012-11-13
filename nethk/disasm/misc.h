/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	misc.h
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

#ifndef MISC_H
#define MISC_H
#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdarg.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// NOTE: start is inclusive, end is exclusive (as in start <= x < end)
#define IS_IN_RANGE(x, s, e) \
( \
	((ULONG_PTR)(x) == (ULONG_PTR)(s) && (ULONG_PTR)(x) == (ULONG_PTR)(e)) || \
	((ULONG_PTR)(x) >= (ULONG_PTR)(s) && (ULONG_PTR)(x) < (ULONG_PTR)(e)) \
)

#if _MSC_VER >= 1400
#pragma warning(disable:4996)
#endif

#if defined(_WIN64)
	#define VALID_ADDRESS_MAX 0x7FFEFFFFFFFFFFFF // Win64 specific
	typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
#else
	#define VALID_ADDRESS_MAX 0x7FFEFFFF // Win32 specific
	typedef unsigned long ULONG_PTR, *PULONG_PTR;
#endif

#ifndef DECLSPEC_ALIGN
	#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
		#define DECLSPEC_ALIGN(x) __declspec(align(x))
	#else
		#define DECLSPEC_ALIGN(x)
	#endif
#endif

#define VALID_ADDRESS_MIN 0x10000    // Win32 specific
#define IS_VALID_ADDRESS(a) IS_IN_RANGE(a, VALID_ADDRESS_MIN, VALID_ADDRESS_MAX+1)

BOOL IsHexChar(BYTE ch);
BYTE *HexToBinary(char *Input, DWORD InputLength, DWORD *OutputLength);

#ifdef __cplusplus
}
#endif
#endif // MISC_H
