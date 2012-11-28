/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	cbuf.c
 * purpose:		winNT-optimized ring buffer
 */

#include <Windows.h>
#include "mincrt/mincrt.h"
#include "mincrt/mincrt_mem.h"

#define FAIL(f) {  _error_message(L#f); /*DebugBreak(); */}

struct ring_buffer
{
	BYTE *address, *_;
	HANDLE hMapFile;

	unsigned long count_bytes;
	unsigned long write_offset_bytes;
	unsigned long read_offset_bytes;
};

/*
 * The code for this function was taken from
 * http://stackoverflow.com/questions/1016888/windows-ring-buffer-without-copying
 */
struct ring_buffer* ring_buffer_create( DWORD bufferSize)
{	
	WCHAR str[256];
	struct ring_buffer* buffer;
	SYSTEM_INFO info;		
	DWORD gran;
	UINT_PTR addr;
	HANDLE hMapFile;
	LPBYTE address, address2;
	static DWORD _id = 0, nTries = 100, i;

	GetSystemInfo(&info);		
	gran = info.dwAllocationGranularity;	
	bufferSize = (bufferSize / gran + 1) * gran;
	for(i = 0; i<nTries; i++) {
		wsprintfW(str, L"Map-%d", _id++);

		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_EXECUTE_READWRITE,
			0,
			bufferSize*2,
			str
			);
		if(hMapFile == NULL) {
			FAIL(CreateFileMapping);
		}	
		address = MapViewOfFile(hMapFile,
			FILE_MAP_ALL_ACCESS,
			0,                   
			0,                   
			bufferSize*2);
		if(address==NULL) {
			FAIL(MapViewOfFile);
			odprintfW(L"Trying again...");
			continue;
		}
		UnmapViewOfFile(address);

		addr = ((UINT_PTR)address);
		address = MapViewOfFileEx(hMapFile,
			FILE_MAP_ALL_ACCESS,
			0,                   
			0,                   
			bufferSize, 
			(LPVOID)addr);
		if(address==NULL) {
			CloseHandle(hMapFile);
			FAIL(MapViewOfFileEx);
			odprintfW(L"Trying again...");
			continue;
		}

		addr = ((UINT_PTR)address) + bufferSize;		
		address2 = MapViewOfFileEx(hMapFile,
			FILE_MAP_ALL_ACCESS,
			0,                   
			0,                   
			bufferSize,
			(LPVOID)addr);	

		if(address2==NULL) {			
			UnmapViewOfFile(address);
			CloseHandle(hMapFile);
			FAIL(MapViewOfFileEx);
			odprintfW(L"Trying again...");
			continue;
		}
		if(!hMapFile || !address || !address2) {					
		} else break;
	}
	
	if(!hMapFile || !address || !address2) {					
		odprintfW(L"cannot create ring buffer");
		DebugBreak();
	}

	buffer = mem_alloc(sizeof(struct ring_buffer));
	buffer->address = address;
	buffer->_ = address2;
	buffer->count_bytes = bufferSize;
	buffer->write_offset_bytes = 0;
	buffer->read_offset_bytes = 0;	
	buffer->hMapFile = hMapFile;

	return buffer;
}

void ring_buffer_free (struct ring_buffer *buffer)
{
	BOOL status;

	status = UnmapViewOfFile(buffer->_);
	if(!status) {
		FAIL(UnmapViewOfFile);
	}
	status = UnmapViewOfFile(buffer->address);
	if(!status) {
		FAIL(UnmapViewOfFile);
	}
	CloseHandle(buffer->hMapFile);

	mem_free(buffer);
}

/*
 * The following code was taken from 
 * http://en.wikipedia.org/wiki/Circular_buffer
 */

void *
	ring_buffer_write_address (struct ring_buffer *buffer)
{
	/*** void pointer arithmetic is a constraint violation. ***/
	return buffer->address + buffer->write_offset_bytes;
}

void
	ring_buffer_write_advance (struct ring_buffer *buffer,
	unsigned long count_bytes)
{
	buffer->write_offset_bytes += count_bytes;
}

void *
	ring_buffer_read_address (struct ring_buffer *buffer)
{
	return buffer->address + buffer->read_offset_bytes;
}

void
	ring_buffer_read_advance (struct ring_buffer *buffer,
	unsigned long count_bytes)
{
	buffer->read_offset_bytes += count_bytes;

	if (buffer->read_offset_bytes >= buffer->count_bytes)
	{
		buffer->read_offset_bytes -= buffer->count_bytes;
		buffer->write_offset_bytes -= buffer->count_bytes;
	}
}

unsigned long
	ring_buffer_count_bytes (struct ring_buffer *buffer)
{
	return buffer->write_offset_bytes - buffer->read_offset_bytes;
}

unsigned long
	ring_buffer_count_free_bytes (struct ring_buffer *buffer)
{
	return buffer->count_bytes - ring_buffer_count_bytes (buffer);
}

void
	ring_buffer_clear (struct ring_buffer *buffer)
{
	buffer->write_offset_bytes = 0;
	buffer->read_offset_bytes = 0;
}

BOOL ring_buffer_put(struct ring_buffer * buffer, void* buf, size_t s) {
	if(ring_buffer_count_free_bytes(buffer) < s)
		return FALSE;
	mem_cpy(ring_buffer_write_address(buffer), buf, s);
	ring_buffer_write_advance(buffer, s);
	return TRUE;
}

BOOL ring_buffer_get(struct ring_buffer * buffer, void* buf, size_t s) {
	if(ring_buffer_count_bytes(buffer) < s)
		return FALSE;
	mem_cpy(buf, ring_buffer_read_address(buffer), s);
	ring_buffer_read_advance(buffer, s);
	return TRUE;
}
