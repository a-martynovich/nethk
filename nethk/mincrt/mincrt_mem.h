//=============================================================================

#ifndef __MINCRT_MEM_H_INCLUDED__
#define __MINCRT_MEM_H_INCLUDED__

//-----------------------------------------------------------------------------

#include <stdint.h>

//-----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------

/*
 * Description:
 *	Initialize mincrt memory.
 *
 * Parameters:
 *	initial_mem_len - Size of the initial memory.
 *
 * Return value:
 *	If the function succeeds, the return value is nonzero.
 *	If the function fails, the return value is zero.
 */
int _mincrt_mem_init(size_t initial_mem_len);

/*
 * Description:
 *	Deinitialize mincrt memory.
 *
 * Parameters:
 *	None.
 *
 * Return value:
 *	If the function succeeds, the return value is nonzero.
 *	If the function fails, the return value is zero.
 */
int _mincrt_mem_deinit();
#ifdef MINCRT
/*
 * Description:
 *	Allocate memory block. The content of the newly allocated block of memory
 *		is not initialized, remaining with indeterminate values.
 *
 * Parameters:
 *	mem_size - Size of the memory block, in bytes.
 *
 * Return value:
 *	If the function succeeds, the return value is a pointer to the allocated
 *		memory block.
 *	If the function failed to allocate the requested block of memory, a null
 *		pointer is returned.
 */
void* mem_alloc(size_t mem_size);

/*
 * Description:
 *	Reallocate memory block. In case that (*p_mem_addr) is 0, the function
 *		behaves exactly as mem_alloc.
 *
 * Parameters:
 *	p_mem_addr - Pointer to a variable that contains the pointer to the block
 *		of memory that the function reallocates. When mem_realloc returns,
 *		p_mem_addr specifies the pointer to the reallocated memory block.
 *	new_mem_size - The new size of the memory block, in bytes.
 *
 * Return value:
 *	If the function succeeds, the return value is nonzero.
 *	If the function fails, the return value is zero.
 */
int mem_realloc(void* p_mem_addr, size_t new_mem_size);

/*
 * Description:
 *	Frees a memory block allocated by the mem_alloc or mem_realloc function.
 *
 * Parameters:
 *	A pointer to the memory block to be freed.
 *
 * Return value:
 *	None.
 */
void mem_free(void* mem_addr);

/*
 * Description:
 *	Compare two blocks of memory.
 *
 * Parameters:
 *	p_mem_1 - Pointer to block of memory.
 *	p_mem_2 - Pointer to block of memory.
 *	mem_len - Number of bytes to compare.
 *
 * Return value:
 *	Returns an integral value indicating the relationship between the content
 *		of the memory blocks:
 *		A zero value indicates that the contents of both memory blocks are
 *			equal.
 *		A value greater than zero indicates that the first byte that does not
 *			match in both memory blocks has a greater value in p_mem_1 than in
 *			p_mem_2 as if evaluated as unsigned char values;
 *		And a value less than zero indicates the opposite.
 */
int mem_cmp(const void* p_mem_1, const void* p_mem_2, size_t mem_len);

/*
 * Description:
 *	Copy block of memory.
 *
 * Parameters:
 *	p_dst_mem - Pointer to the destination array where the content is to be
 *		copied.
 *	p_src_mem - Pointer to the source of data to be copied.
 *	mem_len - Number of bytes to copy.
 *
 * Return value:
 *	None.
 */
void mem_cpy(void* p_dst_mem, const void* p_src_mem, size_t mem_len);

/*
 * Description:
 *	Fill block of memory.
 *
 * Parameters:
 *	p_mem - Pointer to the block of memory to fill.
 *	new_val - Value to be set.
 *	mem_len - Number of bytes to be set to the value.
 *
 * Return value:
 *	None.
 */
void mem_set(void* p_mem, uint8_t new_val, size_t mem_len);


void * mem_move(void * dst, const void * src, size_t count);
#else
#define mem_alloc	malloc
#define mem_cmp		memcmp
#define mem_free	free
#define mem_move	memmove
#define mem_realloc(__buf, __s)	(*__buf = realloc(*__buf, __s))
#define mem_set		memset
#define mem_cpy		memcpy
#endif
void* mem_zalloc(size_t mem_size);
//-----------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

//-----------------------------------------------------------------------------

#endif //__MINCRT_MEM_H_INCLUDED__

//=============================================================================