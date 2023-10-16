#pragma once
#include <stdlib.h>

void* smart_malloc(
	size_t block_size,
	void* copy,
	size_t bytes_copy,
	void (*error_handle)(char* what)
);