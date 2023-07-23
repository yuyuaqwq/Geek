#ifndef GEEK_PROCESS_MEMORY_BLOCK_H_
#define GEEK_PROCESS_MEMORY_BLOCK_H_

#include <string>

#include <Windows.h>

#include <geek/wow64ext/wow64ext.h>

namespace geek {

class MemoryBlock {
public:
  MemoryBlock() {
    base = 0;
    size = 0;
  }

  MemoryBlock(const MEMORY_BASIC_INFORMATION32& entry) {
    base = entry.BaseAddress;
    size = entry.RegionSize;
    protect = entry.Protect;
    state = entry.State;
  }
  MemoryBlock(const MEMORY_BASIC_INFORMATION64& entry) {
    base = entry.BaseAddress;
    size = entry.RegionSize;
    protect = entry.Protect;
    state = entry.State;
  }

  ~MemoryBlock() {

  }

  uint64_t base;
  uint64_t size;
  uint32_t protect;
  uint32_t state;

};

};

#endif // GEEK_PROCESS_MEMORY_BLOCK_H_