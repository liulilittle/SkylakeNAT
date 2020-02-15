#pragma once

#include <stdint.h>

class Memory
{
public:
	static void* Alloc(uint32_t count, uint32_t size);
	static void* Alloc(uint32_t size);
	static void* CAlloc(uint32_t count, uint32_t size);
	static void Free(const void* memory);
	static bool IsNedallocAllocation();
	static bool IsMallocAllocation();
};