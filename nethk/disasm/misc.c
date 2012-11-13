/* 
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	misc.c
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

#include "misc.h"
#include "mincrt/mincrt_mem.h"
#include "mincrt/mincrt_str.h"

BOOL IsHexChar(BYTE ch)
{
	switch (ch)
	{
		case '0': case '1': case '2': case '3': 
		case '4': case '5': case '6': case '7': 
		case '8': case '9': 
		case 'A': case 'a': case 'B': case 'b':
		case 'C': case 'c': case 'D': case 'd':
		case 'E': case 'e': case 'F': case 'f':
			return TRUE;
		default:
			return FALSE;
	}
}

// NOTE: caller must free the buffer returned
BYTE *HexToBinary(char *Input, DWORD InputLength, DWORD *OutputLength)
{
	DWORD i, j, ByteCount = 0;
	char temp_byte[3];
	BYTE *p, *ByteString = NULL;

	if (!InputLength || !OutputLength) return NULL;
	else *OutputLength = 0;

	while (*Input && str_isspace(*Input)) { Input++; InputLength--; }
	if (!*Input) return NULL;
	if (Input[0] == '\"') { Input++; InputLength--; }
	p = (BYTE *)str_chr(Input, '\"');
	if (p) InputLength--;

	if (InputLength > 2 && Input[2] == ' ') // assume spaces
	{
		for (i = 0; i < InputLength; i += 3)
		{
			while (i < InputLength && str_isspace(Input[i])) i++; // skip over extra space, \r, and \n
			if (i >= InputLength) break;

			if (!IsHexChar(Input[i]))
			{
				//fprintf(stderr, "ERROR: invalid hex character at offset %lu (0x%04x)\n", i, i);
				goto abort;
			}

			if (i+1 >= InputLength || !Input[i+1])
			{
				//fprintf(stderr, "ERROR: hex string terminates unexpectedly at offset %lu (0x%04x)\n", i+1, i+1);
				goto abort;
			}

			if (i+2 < InputLength && Input[i+2] && !str_isspace(Input[i+2]))
			{
				//fprintf(stderr, "ERROR: Hex string is malformed at offset %lu (0x%04x)\n", i, i);
				//fprintf(stderr, "Found '%c' (0x%02x) instead of space\n", Input[i+2], Input[i+2]);
				goto abort;
			}

			ByteCount++;
		}

		if (!ByteCount)
		{
			//fprintf(stderr, "Error: no input (byte count = 0)\n");
			goto abort;
		}

		ByteString = mem_alloc(ByteCount+1);
		if (!ByteString)
		{
			//fprintf(stderr, "ERROR: failed to allocate %lu bytes\n", ByteCount);
			goto abort;
		}
			
		mem_set(ByteString, 0, ByteCount+1);
		for (i = 0, j = 0; j < ByteCount; i += 3, j++)
		{			
			while (str_isspace(Input[i])) i++; // skip over extra space, \r, and \n
			temp_byte[0] = Input[i];
			temp_byte[1] = Input[i+1];
			temp_byte[2] = 0;
			ByteString[j] = (BYTE)str_toul(temp_byte, NULL, 16);
		}
	}
	else if (InputLength > 2 && Input[0] == '\\')
	{
		for (i = 0; i < InputLength; i += 2)
		{
			if (Input[i] != '\\' || (Input[i+1] != 'x' && Input[i+1] != '0'))
			{
				//fprintf(stderr, "ERROR: invalid hex character at offset %lu (0x%04x)\n", i, i);
				goto abort;
			}
			i += 2;

			if (!IsHexChar(Input[i]))
			{
				//fprintf(stderr, "ERROR: invalid hex character at offset %lu (0x%04x)\n", i, i);
				goto abort;
			}
			if (i+1 >= InputLength || !Input[i+1])
			{
				//fprintf(stderr, "ERROR: hex string terminates unexpectedly at offset %lu (0x%04x)\n", i+1, i+1);
				goto abort;
			}

			ByteCount++;
		}

		if (!ByteCount)
		{
			//fprintf(stderr, "Error: no input (byte count = 0)\n");
			goto abort;
		}

		ByteString = mem_alloc(ByteCount+1);
		if (!ByteString)
		{
			//fprintf(stderr, "ERROR: failed to allocate %lu bytes\n", ByteCount);
			goto abort;
		}
			
		mem_set(ByteString, 0, ByteCount+1);
		for (i = j = 0; j < ByteCount; i += 2, j++)
		{
			i += 2;
			temp_byte[0] = Input[i];
			temp_byte[1] = Input[i+1];
			temp_byte[2] = 0;
			ByteString[j] = (BYTE)str_toul(temp_byte, NULL, 16);
		}
	}
	else // assume it is a hex string with no spaces with 2 bytes per character
	{
		for (i = 0; i < InputLength; i += 2)
		{
				if (!IsHexChar(Input[i]))
			{
				//fprintf(stderr, "ERROR: invalid hex character at offset %lu (0x%04x)\n", i, i);
				goto abort;
			}
			if (i+1 >= InputLength || !Input[i+1])
			{
				//fprintf(stderr, "ERROR: hex string terminates unexpectedly at offset %lu (0x%04x)\n", i+1, i+1);
				goto abort;
			}

			ByteCount++;
		}

		if (!ByteCount)
		{
			//fprintf(stderr, "Error: no input (byte count = 0)\n");
			goto abort;
		}

		ByteString = mem_alloc(ByteCount+1);
		if (!ByteString)
		{
			//fprintf(stderr, "ERROR: failed to allocate %lu bytes\n", ByteCount);
			goto abort;
		}
			
		mem_set(ByteString, 0, ByteCount+1);
		for (i = 0, j = 0; j < ByteCount; i += 2, j++)
		{
			temp_byte[0] = Input[i];
			temp_byte[1] = Input[i+1];
			temp_byte[2] = 0;
			ByteString[j] = (BYTE)str_toul(temp_byte, NULL, 16);
		}
	}

	*OutputLength = ByteCount;
	return ByteString;

abort:
	if (OutputLength) *OutputLength = 0;
	if (ByteString) mem_free(ByteString);
	return NULL;
}

