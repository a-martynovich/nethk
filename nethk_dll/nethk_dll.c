/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	nethk_dll.c
 * purpose:		dll entrypoint and I/O control
 */

#include <stdint.h>
#include <ws2spi.h>
#include "http_parser.h"
#include "../nethk/mincrt/mincrt.h"
#include "../nethk/nethk.h"
#include "../nethk/cbuf.h"
#include "LiteUnzip.h"

#pragma warning(disable: 4996)	// sprintf is unsafe
#if defined(_TRACE)
#define TRACE odprintfW
#else 
#define TRACE(...)
#endif

#if defined(_TRACE_DATA)
#define TRACE_DATA odputs
#else
#define TRACE_DATA(b, s)
#endif

#if defined(_TRACE_HTTP)
#define TRACE_HTTP odputs
#else
#define TRACE_HTTP(b, s)
#endif

/*
 * _format_data: formats input data for nice output. The format is 
 * as follows:
 * 
 * aaaaaaaaaaaaaaaa <TAB> hh hh hh hh hh hh hh hh hh hh hh hh hh hh hh hh 
 * 
 * where a is <a> buffer character if it is printable, and a dot (.)
 * otherwise, and <hh> is a hex value of the character.
 */
CRITICAL_SECTION csFormatData;	
char* _format_data(DWORD dwDataLength, BYTE* buf) {	
	size_t columns = 16, rows = dwDataLength/columns + (dwDataLength%columns? 1: 0);
	static char* THREAD_SAFE(FALSE) _output=0;
	char* output;
	static size_t THREAD_SAFE(FALSE) output_size = 0;
	size_t i,j,k;

	if(dwDataLength >0 && rows==0) rows = 1;
	else if(dwDataLength==0) return 0;
	EnterCriticalSection(&csFormatData);
		if(output_size < rows*80) {
			output_size = rows*80;
			if(!_output) _output = mem_alloc(output_size);
			else mem_realloc(&_output, output_size);
		}
		output = _output;
		mem_set(output, 0, output_size);
		for(i=0; i<rows; i++) {
			for(j=0; j<columns; j++) {
				UCHAR symbol = '•';
				k = i*columns+j;
				if(k < dwDataLength) 
					symbol = buf[k];

				if(str_isprint(symbol)) {
					if(str_isspace(symbol))
						output+=sprintf(output, " ");
					else output+=sprintf(output, "%c", symbol);
				}
				else output+=sprintf(output, "•");
				//printf(" ");
			}
			output += sprintf(output, "            ");
			for(j=0; j<columns; j++) {
				k = i*columns+j;
				if(k >= dwDataLength) 
					break;

				output+=sprintf(output, "%02x ", buf[k]);
			}
			output+=sprintf(output, "\n");
		}
		i = output - _output;
	LeaveCriticalSection(&csFormatData);
	return _output;
}

#ifdef OUTPUT_PIPE
extern HANDLE hPipe;
DWORD WINAPI _write_pipe(char* buffer, DWORD len) {
	DWORD written = 0;
	size_t i=0;
	static OVERLAPPED ovl;
	mem_set(&ovl, 0, sizeof(ovl));

	if(hPipe != INVALID_HANDLE_VALUE && hPipe != 0) {
		BOOL b = WriteFile(hPipe, buffer, len, &written, &ovl);			
		DWORD e = GetLastError();
		TRACE(L"message written %d bytes\n", len);		
		if(e != ERROR_IO_PENDING && e != NO_ERROR && !b) {
			if(e == ERROR_INVALID_USER_BUFFER || e == ERROR_NOT_ENOUGH_MEMORY) {
				TRACE(L"--- too many overlapped writes");
			}
			else {
				TRACE(L"--- pipe is closed: %d ---\n", e);
				CloseHandle(hPipe);
				hPipe = 0;
			}
		}			
	}
	return 0;
}
#endif


/*
 * _create_pipe:
 *	Creates a thread that tries to keep write-only process pipe open.
 * Arguments: 
 *	pipe_name: the name of the pipe without \\.\pipe\ prefix
 * Returns: 
 *  TRUE on success, FALSE otherwise
*/
#ifdef OUTPUT_PIPE
HANDLE hThread;
DWORD dwThreadID;

BOOL _create_pipe(LPCSTR pipe_name) {
	sprintf(sPipeName, "\\\\.\\pipe\\%s", pipe_name);
	hThread = CreateThread(
		NULL,              // default security
		0,                 // default stack size
		ThreadProc,        // name of the thread function
		NULL,              // no thread parameters
		0,                 // default startup flags
		&dwThreadID);	
	return (hThread!=NULL && hThread!=INVALID_HANDLE_VALUE);
}
#endif

void odputs(char* d, size_t len) {
	DWORD l = str_len(d), i, maxlen = 512;
	TRACE(L"***\t%d bytes\t***", len);		
	for(i = 0; i<l; i+=maxlen) {
		char* _c = d + (i+maxlen> l? l+1: i+maxlen), c = *_c;				
		*_c = 0;
		OutputDebugStringA(d+i);				
		*_c = c;
	}
	OutputDebugStringA("\n");
}

//CRITICAL_SECTION csFilter;
enum nethk_filter _print_traffic(nethk_operation* op) {
  static THREAD_SAFE(FALSE) BYTE* data = NULL;
  static THREAD_SAFE(FALSE) DWORD datalen = 0;
  DWORD addrlen=255, _datalen;
  WCHAR addr[256], *operation_string, *protostring;
  char* formatted_data = NULL;
  //EnterCriticalSection(&csFilter);

	switch(nethk_get_operation(op)) {
	case OP_SEND:
		operation_string = L"send to";
		break;
	case OP_RECV: 
		operation_string = L"recv from";
		break;
	case OP_CONNECT:
		operation_string = L"connect to";
		break; 
	case OP_DISCONNECT:
		operation_string = L"disconnect from";
		break;
	case OP_ACCEPT:
		operation_string = L"accept";
		break;
	};
	
	switch(nethk_get_operation(op)) {
	case OP_SEND:		
	case OP_RECV: {		
		if(nethk_get_data(op, NULL, &_datalen)==E_SUCCESS) {		// get data length first
			if(_datalen) {
				//EnterCriticalSection(&csFilter);
					if(!data) {
						data = mem_alloc(_datalen);
						datalen = _datalen;
					}
					else if (_datalen > datalen) {
						mem_realloc(&data, _datalen);
						datalen = _datalen;
					}
					mem_set(data, 0, datalen);
					nethk_get_data(op, data, &_datalen);
					formatted_data = _format_data(_datalen, data);
				//LeaveCriticalSection(&csFilter);
			}
		}		
	}
	case OP_CONNECT:
	case OP_DISCONNECT:
	case OP_ACCEPT: {
		nethk_get_address_string(op, addr, &addrlen);
	}
	};	
	switch(op->proto) {
	case IPPROTO_ICMP:
		protostring = L"ICMP"; 
		break;
	case IPPROTO_TCP:
		protostring = L"TCP";
		break;
	case IPPROTO_UDP:
		protostring = L"UDP";
		break;
	case IPPROTO_IP:
		protostring = L"(unknown IP proto)";
		break;
	}
	TRACE(L"***\t%s %s %s\t***", operation_string, protostring, addr);
	//EnterCriticalSection(&csFilter);
		if(formatted_data) {
			TRACE_DATA(formatted_data, _datalen);
		}
	//LeaveCriticalSection(&csFilter);
	return FI_PASS;
}

typedef struct {
	http_parser parser;
	http_parser_settings settings;
} http_parser_holder;

typedef enum  {
	HEADER_NOT_IMPORTANT,
	HEADER_CONTENT_LENGTH,
	HEADER_CONTENT_ENCODING
} http_headers;

typedef struct {
	SOCKET s;
	nethk_sockbuf* sockbuf;
	size_t content_length, headers_length, current_chunk_size, target_size;
	http_headers current_header;
	char* current_data, *current_chunk_begin;
	BOOL headers_parsed, content_length_present, gzipped;
	DWORD content_delta;
} http_parser_data;


int _on_header_field(http_parser* parser, const char *at, size_t length) {
	char c = at[length], *data = (char*)at,
		content_length_header[] = "content-length",
		content_encoding_header[] = "content-encoding";
	http_parser_data* parser_data = parser->data;

	data[length] = 0;
	TRACE(L"header field: %hs", data);
	if(!str_icmp(data, content_length_header)) { 
		parser_data->current_header = HEADER_CONTENT_LENGTH;
		parser_data->content_length_present = TRUE;
	} else if(!str_icmp(data, content_encoding_header)) {
		parser_data->current_header = HEADER_CONTENT_ENCODING;
		parser_data->gzipped = FALSE;
	} else
		parser_data->current_header = HEADER_NOT_IMPORTANT;
	data[length] = c;
	return 0;
}
int _on_header_value(http_parser* parser, const char *at, size_t length) {
	char c = at[length], *data = (char*)at;
	http_parser_data* parser_data = parser->data;

	data[length] = 0;
	TRACE(L"header value: %hs", data);
	if(parser_data->current_header == HEADER_CONTENT_LENGTH) {
		parser_data->content_length = a_to_i(at);
	} else if(parser_data->current_header == HEADER_CONTENT_ENCODING) {
		if(!str_icmp(data, "gzip")) {
			parser_data->gzipped = TRUE;
		}
		// TODO: there is also "deflate"
	}
	data[length] = c;
	return 0;
}
/*int _on_body(http_parser* parser, const char *at, size_t length) {
	char c = at[length], *data = at;
	http_parser_data* parser_data = parser->data;

	data[length] = 0;
	TRACE(L"body: %hs content-length: %d", data, parser_data->content_length);
	data[length] = c;
	return 0;
}*/
int _on_message_begin(http_parser* parser) {
	TRACE(L"message begin");
	return 0;
}
int _on_headers_complete(http_parser* parser) {
	http_parser_data* parser_data = parser->data;

	TRACE(L"headers complete");
	parser_data->headers_parsed = TRUE;	
	if(parser->flags & F_CHUNKED) {
		char* end_of_length;
		size_t chunk_length = str_toul(parser_data->current_data + parser->nread, &end_of_length, 16);
		TRACE(L"first chunk length=%d", chunk_length);
		parser_data->headers_length = parser->nread+2;
		parser_data->current_chunk_size = chunk_length;
		parser_data->current_chunk_begin = end_of_length+2;
		parser_data->content_delta = (end_of_length+2) - parser_data->current_data;
		parser_data->target_size = (parser_data->current_chunk_begin - parser_data->current_data) + chunk_length + 2;		// including trailing \r\n
	} else {
		parser_data->headers_length = parser->nread+2;	// including trailing \r\n
		parser_data->target_size = parser_data->headers_length + parser_data->content_length - 2;
	}
	return 0;
}
int _on_message_complete(http_parser* parser) {
	TRACE(L"message complete");
	return 0;
}


enum nethk_filter _http_filter(nethk_operation* op) {	
	// searching for HTTP/1.1 200 OK ... Encoding: chunked
	char http_version[] = "HTTP/1.", http_version_real[9], *data = NULL, *accumulated_data = NULL,
		encoding_chunked[] = "Transfer-Encoding: chunked", *formatted_data, //*http_headers_end,  c,
		sep[] = "\r\n", double_sep[] = "\r\n\r\n", chunks_end[]="\r\n0\r\n\r\n", c;
	DWORD len = sizeof(http_version), accumulated_len = 0;
	int _res;
	BOOL last_chunk_enocountered = FALSE;
	http_parser* parser = NULL; 
	http_parser_settings* settings = NULL;
	http_parser_data* parser_data = NULL;
	nethk_sockbuf* sockbuf = _get_sockbuf(op->s);
	enum nethk_error _err;

	if(nethk_get_operation(op)!=OP_RECV)
		return FI_PASS;
	if(*op->lpNumberOfBytesRecvd == 0) {
		TRACE(L"Zero length message");
		return FI_PASS;
	}
	_err = nethk_get_data(op, http_version_real, &len);
	if(_err != E_SUCCESS && _err != E_DATA_TRUNCATED && len != sizeof(http_version)) {
		DebugBreak();
	}
	//if(http_version_real[len-1]==' ') 
	c = http_version_real[len-1];
		http_version_real[len-1]=0;
	_res = str_cmp(http_version, http_version_real, sizeof(http_version), sizeof(http_version));
	http_version_real[len-1] = c;
	if(_res) {
		// no status code found - may be a continuation of a response
		struct ring_buffer* rb = sockbuf->rb_in;
		if(rb) {
			accumulated_data = ring_buffer_read_address(rb);
			accumulated_len = ring_buffer_count_bytes(rb);
			accumulated_data[accumulated_len] = 0;
		}				
		if(!sockbuf->userdata) {
			TRACE(L"not an HTTP response");
			return FI_PASS;
		}		
		else {
			parser = &((http_parser_holder*)sockbuf->userdata)->parser;
			settings = &((http_parser_holder*)sockbuf->userdata)->settings;
		}
	} else {	// HTTP status code found. Start parsing the response
		parser_data = mem_zalloc(sizeof(http_parser_data));
		parser_data->s = op->s;
		parser_data->sockbuf = sockbuf;
		sockbuf->userdata = mem_zalloc(sizeof(http_parser_holder));		
		parser = &((http_parser_holder*)sockbuf->userdata)->parser;
		settings = &((http_parser_holder*)sockbuf->userdata)->settings;
		parser->data = parser_data;
		http_parser_init(parser, HTTP_RESPONSE);
	}
	
	nethk_get_data(op, NULL, &len);
	data = mem_alloc(len+1);
	nethk_get_data(op, data, &len);
	data[len] = 0;	
	if(!accumulated_data)
		accumulated_data = data;
		
	parser_data = parser->data;
	if(parser_data->headers_parsed == FALSE) {		
		settings->on_header_field = _on_header_field;
		settings->on_header_value = _on_header_value;
		settings->on_headers_complete = _on_headers_complete;
		settings->on_message_begin = _on_message_begin;
		settings->on_message_complete = _on_message_complete;	
	
		parser_data->current_data = data;
		parser_data->target_size = 0;
		http_parser_execute(parser, settings, data, len);

		sockbuf->rb_in = ring_buffer_create (parser_data->target_size );
		if(parser_data->headers_parsed == FALSE) {
			// TODO: return FI_PASS?
			TRACE(L"not done parsing headers");
			DebugBreak();
		}
		if((parser->flags & F_CHUNKED) &&parser_data->current_chunk_size == 0) {
			last_chunk_enocountered = TRUE;
			parser_data->target_size += 5;		// the "0\r\n\r\n"
		}
		if(parser_data->target_size == 0) {
			TRACE(L"Cannot determine length of content");
			DebugBreak();
		}
	}
	while(!last_chunk_enocountered && len+ring_buffer_count_bytes(sockbuf->rb_in) > parser_data->target_size) {
		DWORD _len, _next_chunk_size = 0;
		char* _next_chunk_size_end = 0;		
		if(!(parser->flags & F_CHUNKED)) {		
			// If the encoding is not chunked, the Content-Length should specify data length			
			if(!parser_data->content_length_present) {
				// If there is no Content-Length field in the header, then we believe the message to be complete
				// FIXME: this might not work on slow connections. Actually, we should read the data until the
				// socket closes on remote end.
				parser_data->target_size = len;
				break;
			}
			TRACE(L"somehow there is %d more data than needed", ((len+ring_buffer_count_bytes(sockbuf->rb_in)) - parser_data->target_size));
			//DebugBreak();
			parser_data->target_size = len+ring_buffer_count_bytes(sockbuf->rb_in);		// FIXME: temporary fix
		}
		if(len >= ((len + ring_buffer_count_bytes(sockbuf->rb_in)) - parser_data->target_size)) {			
			// this is the pointer to the next chunk size
			_len = len - ((len + ring_buffer_count_bytes(sockbuf->rb_in)) - parser_data->target_size);	

			_next_chunk_size = str_toul(data + _len, &_next_chunk_size_end, 16);
			TRACE(L"next chunk: %x", _next_chunk_size);
			if(_next_chunk_size == 0) {
				TRACE(L"chunked message received!");
				//DebugBreak();
				//parser_data->target_size += 5;		// the "0\r\n\r\n"
				last_chunk_enocountered = TRUE;
			}
			parser_data->target_size += _next_chunk_size + (_next_chunk_size_end - (data+_len)) + 2;		// including the \r\n
		} else
			break;
	}
	if(ring_buffer_put(sockbuf->rb_in, data, len) == FALSE) {
		struct ring_buffer* rb1;
		// TODO: resize ring buffer to fit data
		TRACE(L"data doesn't fit into the ring buffer. resizing!");
		rb1 = ring_buffer_create(len + ring_buffer_count_bytes(sockbuf->rb_in));
		ring_buffer_put(rb1, ring_buffer_read_address(sockbuf->rb_in), ring_buffer_count_bytes(sockbuf->rb_in));
		ring_buffer_put(rb1, data, len);
		ring_buffer_free(sockbuf->rb_in);
		sockbuf->rb_in = rb1;		
	}
	if ( (!(parser->flags & F_CHUNKED) && ring_buffer_count_bytes(sockbuf->rb_in) == parser_data->target_size) ||
		 ((parser->flags & F_CHUNKED) && last_chunk_enocountered)		
	) {				
		TRACE(L"message received (%d bytes)!", parser_data->target_size);
		sockbuf->rb_out = ring_buffer_create(parser_data->target_size);
		ring_buffer_put(sockbuf->rb_out, ring_buffer_read_address(sockbuf->rb_in), ring_buffer_count_bytes(sockbuf->rb_in));
		ring_buffer_read_advance(sockbuf->rb_in, parser_data->target_size);
		op->dwBytesToRecv = 0;
		formatted_data = _format_data(ring_buffer_count_bytes(sockbuf->rb_out), ring_buffer_read_address(sockbuf->rb_out));
		TRACE_HTTP(formatted_data, ring_buffer_count_bytes(sockbuf->rb_out));

		mem_free(parser_data);
		mem_free(sockbuf->userdata);
		ring_buffer_free(sockbuf->rb_in);
		sockbuf->rb_in = NULL;
		sockbuf->userdata = NULL;

	} else {
		TRACE(L"%d/%d in buffer", ring_buffer_count_bytes(sockbuf->rb_in), parser_data->target_size);
		op->dwBytesToRecv = parser_data->target_size - ring_buffer_count_bytes(sockbuf->rb_in);
		if(!op->dwBytesToRecv && (parser->flags & F_CHUNKED) && !last_chunk_enocountered)
			// we haven't received the last chunk yet, but we don't know the size of the next chunk
			op->dwBytesToRecv = 1;		
	}
/*	http_headers_end = str_str(accumulated_data, double_sep);
	if(http_headers_end) {					
		struct ring_buffer* rb = NULL;
		size_t content_length;

		c = *(http_headers_end+1); *(http_headers_end+1) = 0;
		if(str_str(accumulated_data, encoding_chunked)) {
			char* content;
			DWORD target_length = 0;

			*(http_headers_end+1) = c;
			content_length = str_toul(http_headers_end+sizeof(double_sep)-1, NULL, 16);
			TRACE(L"HTTP chunked length %d bytes", content_length);
			content = str_str(http_headers_end+sizeof(double_sep)-1, sep)+sizeof(sep)-1;
			target_length = (content-accumulated_data)+content_length;
			rb = _get_sockbuf(op->s)->rb_in;
			if(!rb) {
				_get_sockbuf(op->s)->rb_in = rb = ring_buffer_create(target_length+32);
			}			
			if(!str_cmp(data+len-str_len(chunks_end), chunks_end, sizeof(chunks_end), sizeof(chunks_end)) && 
				ring_buffer_count_bytes(rb) >= target_length ) {
				TRACE(L"HTTP last chunk received");
			}
			ring_buffer_put(rb, data, len);
		} else {
			size_t content_length=0;
			char content_length_field[] = "Content-Length: ", *content_length_val;

			c = *(http_headers_end+1); *(http_headers_end+1) = 0;
			if(content_length_val = str_str(accumulated_data, content_length_field)) {
				content_length = a_to_i(content_length_val + sizeof(content_length_field)-1);
			} else {
				TRACE(L"HTTP plain encoding: Content-Length not found", content_length);
			}

			TRACE(L"HTTP plain encoding lentgh=%d", content_length);
			*(http_headers_end+1) = c;
		}
	} else {				
		TRACE(L"HTTP headers end not found");
	}*/
	mem_free(data);
	return FI_QUEUE;
}
/*
 * DllMain: dll entrypoint. Initializes mincrt memory, installs hooks,
 * opens named pipe if OUTPUT_PIPE is defined.
 */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	BOOL success;
	static nethk_handler my_handler, http_handler;
#ifdef OUTPUT_PIPE
	CHAR pid_str[16];
#endif
	UNREFERENCED_PARAMETER(hinst);
	UNREFERENCED_PARAMETER(reserved);	

	if (dwReason == DLL_PROCESS_ATTACH) {
		TRACE(L"nethk starting...");	
		//InitializeCriticalSectionAndSpinCount(&csFilter, 0x400);
		InitializeCriticalSectionAndSpinCount(&csFormatData, 0x400);
		success = nethk_install();

		if (success == TRUE) {
			TRACE(L"--- hook ok ---");
		}
		else {
			TRACE(L"--- cannot hook ---");			
			return FALSE;
		}
		my_handler.proto = IPPROTO_TCP;
		my_handler.family = IPPROTO_IP;
		my_handler.filter = _print_traffic;
		nethk_add_handler(&my_handler);

		http_handler.proto = IPPROTO_TCP;
		http_handler.family = IPPROTO_IP;
		http_handler.filter = _http_filter;
		nethk_add_handler(&http_handler);
#ifdef OUTPUT_PIPE
		sprintf(pid_str, "Nethk%d", GetCurrentProcessId());
		_create_pipe(pid_str);
#endif
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		success = nethk_uninstall();
//		DeleteCriticalSection(&csFilter);
		DeleteCriticalSection(&csFormatData);
		TRACE(L"--- removed: %s ---\n", success==TRUE? L"SUCCESS": L"FAIL");		
#ifdef OUTPUT_PIPE
		if(hThread && hThread!=INVALID_HANDLE_VALUE) {
			TerminateThread(hThread, 0);
		}		
#endif
	}
	return TRUE;
}
