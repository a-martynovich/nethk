/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	cbuf.c
 * purpose:		winNT-optimized ring buffer
 */

#include <Windows.h>

#define FAIL(f) { _error_message(L#f); __debugbreak(); }
#define TRACE odprintfW

__inline void odprintfW(PCWSTR format, ...) {
	WCHAR _buf[1024];	// this is the maximum size supported by wvsprintf
	va_list	args;	
	int len;
	va_start(args, format);	
	len = wvsprintfW(_buf, format, args);//wvnsprintfW(_buf, 256-2, format, args);
	if (len > 0) {
		_buf[len++] = L'\r';
		_buf[len++] = L'\n';
		_buf[len] = L'\0';
		OutputDebugStringW(_buf);
	}
}

void _error_message(LPWSTR lpszFunction) 
{ 
	// Retrieve the system error message for the last-error code
	LPWSTR lpMsgBuf = malloc(1024*sizeof(WCHAR)),
		lpDisplayBuf = malloc(1024*sizeof(WCHAR));
	DWORD dw = GetLastError(); 
	HMODULE m = LoadLibrary(L"wininet.dll");

	FormatMessage(
		//FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_HMODULE,
		m,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		lpMsgBuf,
		1024, NULL );

	//wsprintfW(lpDisplayBuf, L"%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf); 
	//TRACE(lpDisplayBuf);
	odprintfW(L"%s failed with error %d: %s\n", lpszFunction, dw, lpMsgBuf);
	free(lpMsgBuf);
	free(lpDisplayBuf);
}


struct ring_buffer
{
	BYTE *address, *_;
	HANDLE hMapFile;

	unsigned long count_bytes;
	unsigned long write_offset_bytes;
	unsigned long read_offset_bytes;
};

/*
 * The idea for the code for this function was taken from
 * http://stackoverflow.com/questions/1016888/windows-ring-buffer-without-copying
 */
struct ring_buffer* ring_buffer_create( DWORD bufferSize, DWORD id )
{	
	WCHAR str[256];
	struct ring_buffer* buffer;
	SYSTEM_INFO info;		
	DWORD gran;
	UINT_PTR addr;
	HANDLE hMapFile;
	LPVOID address, address2;

	GetSystemInfo(&info);		
	gran = info.dwAllocationGranularity;
	// note that the base address must be a multiple of the allocation granularity
	bufferSize = (bufferSize / gran+1) * gran;
	wsprintfW(str, L"Local\\Map-%d", id);

	//buffer = mem_alloc(sizeof(struct ring_buffer));
	hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_EXECUTE_READWRITE,
		0,
		bufferSize*2,
		str
		);
	if(hMapFile == NULL || hMapFile==INVALID_HANDLE_VALUE) {
		FAIL(CreateFileMapping);
	}	
	address = MapViewOfFile(hMapFile,
		FILE_MAP_ALL_ACCESS,
		0,                   
		0,                   
		bufferSize*2);
	if(address==NULL) {
		FAIL(MapViewOfFile);
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
		FAIL(MapViewOfFileEx);
	}

	addr = ((UINT_PTR)address) + bufferSize;		
	address2 = MapViewOfFileEx(hMapFile,
		FILE_MAP_ALL_ACCESS,
		0,                   
		0,                   
		bufferSize,
		(LPVOID)addr);	

	if(address2==NULL) {
		FAIL(MapViewOfFileEx);
	}
	if(!hMapFile || !address || !address2) {		
		return NULL;
	} else TRACE(L"buffer size 0x%X created", bufferSize);

	buffer = malloc(sizeof(struct ring_buffer));
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
		//report_exceptional_condition();
	}
	status = UnmapViewOfFile(buffer->address);
	if(!status) {
		//report_exceptional_condition();
	}
	CloseHandle(buffer->hMapFile);

	free(buffer);
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
	memcpy(ring_buffer_write_address(buffer), buf, s);
	ring_buffer_write_advance(buffer, s);
	return TRUE;
}

BOOL ring_buffer_get(struct ring_buffer * buffer, void* buf, size_t s) {
	if(ring_buffer_count_bytes(buffer) < s)
		return FALSE;
	memcpy(buf, ring_buffer_read_address(buffer), s);
	ring_buffer_read_advance(buffer, s);
	return TRUE;
}

#include <math.h>
int _random(int _max) {
	return (int)ceil((double)rand()/(double)RAND_MAX*(double)_max);
}

int main1(int argc, CHAR* argv[]) {
	struct ring_buffer *rb_in = ring_buffer_create(1,0), 
		*rb_out = ring_buffer_create(1,1), 
		*rb_inout = ring_buffer_create(1,2);
	size_t N = ring_buffer_count_free_bytes(rb_in), i, s;
	WORD* numbers = malloc(N);	
	for(i=0; i<N/2; i++) {
		numbers[i] = rand();
	}
	ring_buffer_put(rb_in, numbers, N);
	
	srand(GetCurrentProcessId());
	while(TRUE) {
		if(rand() > RAND_MAX/2) {
			s = _random(N/4);
			if(s > ring_buffer_count_bytes(rb_in) || s > ring_buffer_count_free_bytes(rb_inout)) {
				if(ring_buffer_count_free_bytes(rb_inout) > ring_buffer_count_bytes(rb_in))
					s = ring_buffer_count_bytes(rb_in);
				else
					s = ring_buffer_count_free_bytes(rb_inout);
			}
			if(s > 0) {				
				ring_buffer_get(rb_in, ring_buffer_write_address(rb_inout), s);
				ring_buffer_write_advance(rb_inout, s);
				TRACE(L"in -> inout %d", s);
			}			
		} else {
			s = _random(N/2);
			if(s > ring_buffer_count_bytes(rb_inout) || s > ring_buffer_count_free_bytes(rb_out)) {
				if(ring_buffer_count_free_bytes(rb_out) > ring_buffer_count_bytes(rb_inout))
					s = ring_buffer_count_bytes(rb_inout);
				else
					s = ring_buffer_count_free_bytes(rb_out);
			}
			if(s > 0) {				
				ring_buffer_get(rb_inout, ring_buffer_write_address(rb_out), s);
				ring_buffer_write_advance(rb_out, s);
				TRACE(L"inout -> out %d", s);
			}
		}
		if(ring_buffer_count_bytes(rb_in)==0 && ring_buffer_count_bytes(rb_inout)==0)
			break;
	}

	TRACE (L"memcmp returned %d", memcmp(numbers, ring_buffer_read_address(rb_out), ring_buffer_count_bytes(rb_out))); 
	return 0;
}
