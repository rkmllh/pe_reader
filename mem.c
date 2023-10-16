#include "mem.h"
#include <string.h>

#define memzero(base, size)      \
      memset(base, 0, size);

void* smart_malloc(
	size_t block_size,
	void* copy,
	size_t bytes_copy,
	void (*error_handle)(char* what)
)
{
	void* mem_block = malloc(block_size);
	if (mem_block == NULL && error_handle)
		error_handle("malloc");
	if (mem_block)
	{
		memzero(mem_block, block_size);
		if (copy != NULL)
			memcpy(mem_block, copy, bytes_copy);
	}

	return mem_block;
}