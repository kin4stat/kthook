#ifndef KTHOOK_PLATFORM_LINUX_MEMORY_HPP_
#define KTHOOK_PLATFORM_LINUX_MEMORY_HPP_
namespace kthook::platform {
namespace detail {
struct map_info {
  std::uintptr_t start;
  std::uintptr_t end;

  unsigned prot;
};


inline std::vector<map_info> parse_proc_maps() {
  std::vector<map_info> result;

#ifdef __FreeBSD__
  std::ifstream proc_maps{"/proc/curproc/map"};
#else
  std::ifstream proc_maps{"/proc/self/maps"};
#endif // #ifdef __FreeBSD__
  std::string line;

  while (std::getline(proc_maps, line)) {
    map_info parse_result{};

    auto start = 0u;
    auto i = 0u;
    while (line[i] != '-') { ++i; }

    std::from_chars(&line[start], &line[i], parse_result.start, 16);

    start = ++i;
    while (line[i] != '\t' && line[i] != ' ') { ++i; }
    std::from_chars(&line[start], &line[i], parse_result.end, 16);
    
#ifdef __FreeBSD__
    while (line[i] != '\t' && line[i] != ' ') { ++i; } ++i; // skip
    while (line[i] != '\t' && line[i] != ' ') { ++i; } ++i; // skip
    while (line[i] != '\t' && line[i] != ' ') { ++i; } ++i; // skip
#endif // #ifdef __FreeBSD__
    
    start = ++i;
    while (line[i] != '\t' && line[i] != ' ') { ++i; }

    if (line[start++] == 'r')
      parse_result.prot |= PROT_READ;
    if (line[start++] == 'w')
      parse_result.prot |= PROT_WRITE;
    if (line[start++] == 'x')
      parse_result.prot |= PROT_EXEC;
    result.push_back(parse_result);
  }
  return result;
}
}

/**
 * @brief Flushes CPU Instruction cache
 * @param ptr pointer to instructions
 * @param size size, in bytes
 * @return was the operation successful
 */
inline bool flush_instruction_cache(const void* ptr, std::size_t size) {
  return __builtin___clear_cache(ptr, static_cast<unsigned char*>(ptr) + size);
}

inline MemoryProt get_memory_prot(const void* addr) {
    auto map_infos = parse_proc_maps();

    std::uintptr_t iaddr = reinterpret_cast<std::uintptr_t>(addr);

    for (auto& mi : map_infos) {
        if (mi.start <= iaddr && iaddr < mi.end) {
            if ((mi.prot & PROT_EXEC) && (mi.prot & PROT_READ)) {
                return MemoryProt::PROTECT_RE;
            }
            if ((mi.prot & PROT_EXEC) && (mi.prot & PROT_READ) && (mi.prot & PROT_WRITE)) {
                return MemoryProt::PROTECT_RWE;
            }
            if ((mi.prot & PROT_WRITE) && (mi.prot & PROT_READ)) {
                return MemoryProt::PROTECT_RW;
            }
        }
    }

    return MemoryProt::PROTECT_RE;
}

/**
 * @brief Checks whether the memory region at the address is executable
 * @param addr address to check
 * @return is memory region at the address is executable
 */
inline bool check_is_executable(const void* addr) {
  auto map_infos = kthook::detail::parse_proc_maps();

  std::uintptr_t iaddr = reinterpret_cast<std::uintptr_t>(addr);

  for (auto& mi : map_infos) {
      if (mi.start <= iaddr && iaddr < mi.end) {
          if (mi.prot & PROT_EXEC) {
              return true;
          }
      }
  }

  return false;
}

/**
 * @brief Sets memory region protection
 * @param addr address of the region(may be unaligned to page boundary)
 * @param size count, in bytes
 * @param protectMode new protection mode
 * @return was the operation successful
 */
inline bool set_memory_prot(const void* addr, std::size_t size, MemoryProt protectMode) {
  const int c_rw = PROT_READ | PROT_WRITE;
  const int c_rwe = PROT_READ | PROT_WRITE | PROT_EXEC;
  const int c_re = PROT_READ | PROT_EXEC;
  int mode;
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
  size_t pageSize = sysconf(_SC_PAGESIZE);
  size_t iaddr = reinterpret_cast<size_t>(addr);
  size_t roundAddr = iaddr & ~(pageSize - static_cast<size_t>(1));
  return mprotect(reinterpret_cast<void*>(roundAddr), size + (iaddr - roundAddr), mode) == 0;
}

inline MemoryProt get_memory_prot(const void* addr) {
  auto map_infos = parse_proc_maps();

  std::uintptr_t iaddr = reinterpret_cast<std::uintptr_t>(addr);

  for (auto& mi : map_infos) {
      if (mi.start <= iaddr && iaddr < mi.end) {
          if ((mi.prot & PROT_EXEC) && (mi.prot & PROT_READ)) {
              return MemoryProt::PROTECT_RE;
          }
          if ((mi.prot & PROT_EXEC) && (mi.prot & PROT_READ) && (mi.prot & PROT_WRITE)) {
              return MemoryProt::PROTECT_RWE;
          }
          if ((mi.prot & PROT_WRITE) && (mi.prot & PROT_READ)) {
              return MemoryProt::PROTECT_RW;
          }
      }
  }

  return MemoryProt::PROTECT_RE;
}
}
#endif // KTHOOK_PLATFORM_LINUX_MEMORY_HPP_