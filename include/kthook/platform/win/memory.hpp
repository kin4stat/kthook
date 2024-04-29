#ifndef KTHOOK_PLATFORM_WIN_MEMORY_HPP_
#define KTHOOK_PLATFORM_WIN_MEMORY_HPP_

namespace kthook::platform {
/**
 * @brief Flushes CPU Instruction cache
 * @param ptr pointer to instructions
 * @param size size, in bytes
 * @return was the operation successful
 */
inline bool flush_instruction_cache(const void* ptr, std::size_t size) {
  return FlushInstructionCache(GetCurrentProcess(), ptr, size) != 0;
}

/**
 * 
 * @param addr address
 * @return memory protection on requested address
 */
inline MemoryProt get_memory_prot(const void* addr) {
    MEMORY_BASIC_INFORMATION buffer;
    VirtualQuery(addr, &buffer, sizeof(buffer));
    if (buffer.Protect == PAGE_EXECUTE_READ) {
        return MemoryProt::PROTECT_RE;
    }
    if (buffer.Protect == PAGE_EXECUTE_READWRITE) {
        return MemoryProt::PROTECT_RWE;
    }
    if (buffer.Protect == PAGE_READWRITE) {
        return MemoryProt::PROTECT_RW;
    }
    return MemoryProt::PROTECT_RE;
}

/**
 * @brief Checks whether the memory region at the address is executable
 * @param addr address to check
 * @return is memory region at the address is executable
 */
inline bool check_is_executable(const void* addr) {
  MEMORY_BASIC_INFORMATION buffer;
  VirtualQuery(addr, &buffer, sizeof(buffer));
  return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ ||
         buffer.Protect == PAGE_EXECUTE_READWRITE || buffer.Protect == PAGE_EXECUTE_WRITECOPY;
}

/**
 * @brief Sets memory region protection
 * @param addr address of the region(may be unaligned to page boundary)
 * @param size count, in bytes
 * @param protectMode new protection mode
 * @return was the operation successful
 */
inline bool set_memory_prot(const void* addr, std::size_t size, MemoryProt protectMode) {
  const DWORD c_rw = PAGE_READWRITE;
  const DWORD c_rwe = PAGE_EXECUTE_READWRITE;
  const DWORD c_re = PAGE_EXECUTE_READ;
  DWORD mode;
  switch (protectMode) {
    case MemoryProt::PROTECT_RW:
      mode = c_rw;
      break;
    case MemoryProt::PROTECT_RWE:
      mode = c_rwe;
      break;
    case MemoryProt::PROTECT_RE:
      mode = c_re;
      break;
    default:
      return false;
  }
  DWORD oldProtect;
  return VirtualProtect(const_cast<void*>(addr), size, mode, &oldProtect) != 0;
}
}
#endif