/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	nethk.h
 * purpose:		nethk API declaration
 */

#define THREAD_SAFE(b)

/*
 * nethk_install: 
 *	Installs runtime code hooks on all WinAPI WSP* functions. All the hooks are 
 *	default functions (defined in HOOK_IMPL) which do nothing, except for WSPRecv, WSPRecvFrom,
 *	WSPSend, WSPSendTo, WSPGetOverlappedResult.
 * Returns: 
 *	TRUE on success; FALSE if one of the functions could not be hooked.
 */
BOOL nethk_install();

/*
 * nethk_uninstall: 
 *	Uninstalls all hooks installed by nethk_install.
 * Returns:
 *	TRUE on success; FALSE if one of the functions could not be unhooked.
 */
BOOL nethk_uninstall();

/*
 * get_sockproctable: 
 *	Finds SOCKPROCTABLE pointer in memory.
 *	It finds an address of WSPStartup and searches area around it for marker 
 *	code surrounding SOCKPROCTABLE object in process memory.
 * Returns: 
 *	a pointer to SOCKPROCTABLE on success; NULL on failure.
 */
LPWSPPROC_TABLE get_sockproctable();

enum nethk_operation_type {
	OP_INVALID, OP_RECV = 'r', OP_SEND = 's', OP_CONNECT = 'c', OP_ACCEPT = 'a', OP_UNKNOWN = 'u', OP_DISCONNECT = 'd'
};
enum nethk_filter {
	FI_DROP, FI_PASS, FI_FILTER, FI_QUEUE, FI_ERROR
};

enum nethk_error {
	E_SUCCESS, E_DATA_TRUNCATED, E_INVALID_ARG
};

typedef struct _OPERATION {
	char op;
	int res;

	LPWSABUF lpBuffers;
	DWORD dwBufferCount;
	LPDWORD lpNumberOfBytesRecvd;
	DWORD dwBytesToRecv;

	LPWSAOVERLAPPED lpOverlapped;
	LPVOID lpOverlapped_Pointer;
	HANDLE lpOverlapped_hEvent;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine;
	LPWSATHREADID lpThreadId;

	LPINT lpErrno;

	SOCKADDR_STORAGE addr;
	struct sockaddr* lpAddr;
	LPINT lpAddrLen;
	INT addrLen;
	IPPROTO proto;

	SOCKET s;
} nethk_operation, *LPOPERATION;

/*
 * nethk_filter:
 *   Callback function. Should return one of the nethk_filter enum members:
 *   FI_DROP: drop the data. A receive or send operation will complete with error. No other callbacks will be called.
 *   FI_PASS: do nothing, just pass the data to the application. Next callback will be called.
 *   FI_FILTER: the callback has modified the data. No other callbacks will be called.
 *   FI_QUEUE: the callback wants more data in queue. No other callbacks will be called. 
 */
typedef enum nethk_filter (*nethk_filter_func_t)(nethk_operation*);

/*
 * struct nethk_handler:
 *   Defines handler information: socket family and protocol, and a user callback (filter).
 *     family: AF_INET, AF_INET6, AF_UNSPEC (for both)
 *     proto: any of IPPROTO_*
 *     filter: see above
 *     next: reserved. do no use.
 */
typedef struct _nethk_handler {	
	short family;	// AF_*
	short proto;	// IPPROTO_*
	nethk_filter_func_t filter;

	struct _nethk_handler* next;	
} nethk_handler;

typedef struct ring_buffer *LPRINGBUFFER;
typedef struct {
	SOCKET s;
	LPRINGBUFFER rb_in, rb_out;
	void* userdata;
} nethk_sockbuf;
/*
 * nethk_add_handler:
 *   Add a handler to the end of the handlers list.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if h is invalid
 */
enum nethk_error nethk_add_handler(nethk_handler* h/*, nethk_handler* before*/);

/*
 * nethk_remove_handler:
 *   Remove a handler from the handlers list.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if h is invalid or not found in the list
 */
enum nethk_error nethk_remove_handler(nethk_handler* h);

/*
 * nethk_get_data:
 *   put the data obtained from the operation op into a buffer buf which length is len
 *   and set len to the size of the actual data. If called with buf==NULL, only len
 *   is modified.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if op is invalid; E_DATA_TRUNCATED if 
 *   the length of buf is less than required.
 */
enum nethk_error nethk_get_data(const nethk_operation* op, BYTE* buf, LPDWORD len);

/*
 * nethk_get_data:
 *   get the data obtained from the buffer buf which length is len and put it into a buffer
 *   of operation object op.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if op is invalid; E_DATA_TRUNCATED if 
 *   the length of buf is more than the length of the buffer of the operation.
 */
enum nethk_error nethk_set_data(nethk_operation* op, BYTE* buf, LPDWORD lpBuflen);

/*
 * nethk_get_operation:
 *   get the type of the operation.
 * Returns:
 *   The type of the operation, if op is valid. OP_UNKNOWN otherwise.
 */
enum nethk_operation_type nethk_get_operation(const nethk_operation* op);

/*
 * nethk_get_address_string:
 *   get the human-readable representation of the target address of the operation op.
 *   Put the address string into addr, and its length (in characters) into addrlen.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if either op or addrlen is invalid.
 */
enum nethk_error nethk_get_address_string(const nethk_operation* op, WCHAR* addr, LPDWORD addrlen);

/*
 * nethk_get_address:
 *   get the sockaddr-encoded target address of the operation op.
 * Returns:
 *   E_SUCCESS on success; E_INVALID_ARG if either op or addrlen is invalid.
 */
enum nethk_error nethk_get_address(const nethk_operation* op, struct sockaddr* lpAddr, LPDWORD addrlen);

/*
 * _get_sockbuf: 
 *	Returns a nethk_sockbuf object containing two ring buffers. The first, rb_in,
 *	is to use be handlers. The second, rb_out, is to use by nethk. When a handler
 *	receives data it can store it in rb_in. When it is done with data accumulated
 *	in rb_in, it should clear rb_in and write it to rb_out, so that the data could
 *	be given to an application.
 *	The object exists for every socket. But there is a limited number of sockets
 *	for which the objects exist simultaneously (NETHK_OPERATIONS_N). You will get
 *	a NULL instead of nethk_sockbuf if there're too much nethk_sockbuf objects.
 * Returns: 
 *	A nethk_sockbuf object if possible; NULL otherwise.
 */
nethk_sockbuf* _get_sockbuf(SOCKET s);