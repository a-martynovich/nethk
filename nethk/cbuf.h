/*
 * Developed by Artem Martynovich for MOBILE PRO TECH.
 * project:		nethk
 * filename:	cbuf.h
 * purpose:		winNT-optimized ring buffer
 */

extern struct ring_buffer;
struct ring_buffer* ring_buffer_create (size_t bufferSize);
void ring_buffer_free (struct ring_buffer *buffer);
void * ring_buffer_write_address (struct ring_buffer *buffer);
void ring_buffer_write_advance (struct ring_buffer *buffer, unsigned long count_bytes);
void * ring_buffer_read_address (struct ring_buffer *buffer);
void ring_buffer_read_advance (struct ring_buffer *buffer, unsigned long count_bytes);
size_t ring_buffer_count_bytes (struct ring_buffer *buffer);
size_t ring_buffer_count_free_bytes (struct ring_buffer *buffer);
void ring_buffer_clear (struct ring_buffer *buffer);
BOOL ring_buffer_put(struct ring_buffer * buffer, void* buf, size_t s);
BOOL ring_buffer_get(struct ring_buffer * buffer, void* buf, size_t s);
