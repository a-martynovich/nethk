//=============================================================================

#include "mincrt_mem.h"

#include <windows.h>

//-----------------------------------------------------------------------------

static int		m_heap_created;
static HANDLE	m_h_heap;

//-----------------------------------------------------------------------------

int _mincrt_mem_init(size_t initial_mem_len)
{
	m_heap_created = 1;

	m_h_heap = HeapCreate(0, initial_mem_len, 0);

	if (!m_h_heap)
	{
		m_heap_created = 0;

		m_h_heap = GetProcessHeap();
	}

	return (m_h_heap != 0);
}

//-----------------------------------------------------------------------------

int _mincrt_mem_deinit()
{
	int	result = 0;

	if ((m_heap_created) && (m_h_heap))
	{
		if (!HeapDestroy(m_h_heap))
			result = 0;
		else
			m_h_heap = 0;
	}

	return result;
}

//-----------------------------------------------------------------------------

void* mem_alloc(size_t mem_size)
{
	void*	result = 0;

	if (mem_size)
		result = HeapAlloc(m_h_heap, 0, mem_size);

	return result;
}

//-----------------------------------------------------------------------------

int mem_realloc(void* p_mem_addr, size_t new_mem_size)
{
	int	result = 0;

	if ((m_h_heap) && (p_mem_addr) && (new_mem_size > 0))
	{
		if (*(void**)p_mem_addr == 0)
		{
			*(void**)p_mem_addr = mem_alloc(new_mem_size);

			result = (*(void**)p_mem_addr != 0);
		}
		else
		{
			void* temp_addr = HeapReAlloc(
				m_h_heap, 0, *(void**)p_mem_addr, new_mem_size
				);

			if (temp_addr)
			{
				*(void**)p_mem_addr = temp_addr;
				result = 1;
			}
		}
	}

	return result;
}

//-----------------------------------------------------------------------------

void mem_free(void* mem_addr)
{
	HeapFree(m_h_heap, 0, mem_addr);
}

//-----------------------------------------------------------------------------

int mem_cmp(const void* p_mem_1, const void* p_mem_2, size_t mem_len)
{
	register uint8_t	m1, m2;
	register size_t		i;

	for (i = 0; i < mem_len; i++)
	{
		m1 = ((uint8_t*)p_mem_1)[i];
		m2 = ((uint8_t*)p_mem_2)[i];

		if (m1 != m2)
			return (int)(m1 - m2);
	}

	return 0;
}

//-----------------------------------------------------------------------------

void mem_cpy(void* p_dst_mem, const void* p_src_mem, size_t mem_len)
{
	register size_t i;

	for (i = 0; i < mem_len; i++)
	{
		((uint8_t*)p_dst_mem)[i] = ((LPBYTE)p_src_mem)[i];

		if (i == 0) i = 0; // optimization bypass
	}
}
#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t len) {
	mem_cpy(dst, src, len);
	return dst;
}
//-----------------------------------------------------------------------------

void mem_set(void* p_mem, uint8_t new_val, size_t mem_len)
{
	register size_t i = mem_len;

	while (i--)
		((uint8_t*)p_mem)[i] = new_val;
}
#pragma function(memset)
void* memset(void* p_mem, int new_val, size_t mem_len) {
	mem_set(p_mem, new_val, mem_len);
	return p_mem;
}

// memmove is defined first so it will use the intrinsic memcpy
void * mem_move(void * dst, const void * src, size_t count) {
	void * ret = dst;

	if (dst <= src || (char *)dst >= ((char *)src + count)) {
		// Non-Overlapping Buffers - copy from lower addresses to higher addresses
		// saves 500 bytes of 1.4MB in uncompressed setup.exe, worth it?
		mem_cpy(dst, src, count);
		// while (count--) {
		//     *(char *)dst = *(char *)src;
		//     dst = (char *)dst + 1;
		//     src = (char *)src + 1;
		// }
	}
	else {
		// Overlapping Buffers - copy from higher addresses to lower addresses
		dst = (char *)dst + count - 1;
		src = (char *)src + count - 1;

		while (count--) {
			*(char *)dst = *(char *)src;
			dst = (char *)dst - 1;
			src = (char *)src - 1;
		}
	}

	return(ret);
}


//=============================================================================
