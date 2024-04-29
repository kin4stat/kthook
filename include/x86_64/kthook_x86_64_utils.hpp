#ifndef KTHOOK_X86_64_UTILS_HPP_
#define KTHOOK_X86_64_UTILS_HPP_

namespace kthook::detail {
#ifndef _WIN32
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
#endif // #ifndef _WIN32
}

namespace kthook::utils {
/**
 * @brief Function for scanning the maximum number of bytes that can be overwritten without breaking anything
 * @param hook_address address for scanning
 * @param limit The value at which the scan will be stopped
 * @return count of available bytes for rewriting without code break
 */
inline std::size_t get_available_hook_size(std::uintptr_t hook_address, std::size_t limit = 16) {
  /*
    To detect available hook size we loop through instructions until we don't find ret or reach limit
    
    For short jumps, we save max_ref_address, so we can recognize situation like this:
    
    test eax, eax
    je L1
    ; some code
    ret
  L1:
    ; some code

    if in this situation we will patch after ret instruction, we will break code in L1


    For situations like this:
  L1:
  ; some code
  hook_address:
  ; some code
  jmp L1

    loop should end at jmp
  */
  std::uintptr_t current_address = hook_address;
  std::uintptr_t max_jmp_ref = 0;
  bool finished = false;

  while (!finished) {
    detail::hde hs;
    hde_disasm(reinterpret_cast<void*>(current_address), &hs);
    if (hs.flags & F_ERROR) return false;
    if (current_address - hook_address >= limit) {
      finished = true;
    }
    // Relative Call
    else if (hs.opcode == 0xE8) {
      // just skip, doesn't matter for maximum size analysis
    }
    // Relative jmp
    else if ((hs.opcode & 0xFD) == 0xE9) {
      std::uintptr_t jmp_destination = current_address + hs.len;

      if (hs.opcode == 0xEB) // is short jump
        jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
      else
        jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

      // if jump destination less than limit address, and its 1 byte jmp, we save destination as max reference
      // else if jmp refers to address less than hook address we finish our analysis
      if (hook_address <= jmp_destination && jmp_destination < hook_address + limit && hs.opcode == 0xEB) {
        if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
      } else {
        finished = (hook_address >= jmp_destination);
      }
    }
    // Conditional relative jmp
    else if (((hs.opcode & 0xF0) == 0x70) || // one byte jump
             ((hs.opcode & 0xFC) == 0xE0) || // LOOPNZ/LOOPZ/LOOP/JECXZ
             ((hs.opcode2 & 0xF0) == 0x80)) {
      // two byte jump

      std::uintptr_t jmp_destination = current_address + hs.len;

      if ((hs.opcode & 0xF0) == 0x70     // Jcc
          || (hs.opcode & 0xFC) == 0xE0) // LOOPNZ/LOOPZ/LOOP/JECXZ
        jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
      else
        jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

      if (hook_address <= jmp_destination && jmp_destination < hook_address + limit &&
          ((hs.opcode & 0xF0) == 0x70 || (hs.opcode & 0xFC) == 0xE0)) {
        if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
      }
    }
    // RET
    else if ((hs.opcode & 0xFE) == 0xC2) {
      finished = (current_address < max_jmp_ref);
    }
    current_address += hs.len;
  }
  return current_address - hook_address;
}

/**
 * @brief Can be used to obtain relative address
 * @param dest destination address
 * @param src source address
 * @param oplen length of the whole instruction, which is using relative address encoding
 * @return relative address, from src to dest
 */
inline std::uintptr_t get_relative_address(std::uintptr_t dest, std::uintptr_t src, std::size_t oplen = 5) {
  return dest - src - oplen;
}

/**
 * @brief Can be used to restore absolute address from relative address
 * @param RIP address of the instruction, which is using relative address encoding
 * @param rel relative address(instruction operand)
 * @param oplen length of the whole instruction, which is using relative address encoding
 * @return absolute address
 */
inline std::uintptr_t restore_absolute_address(std::uintptr_t RIP, std::uintptr_t rel, std::size_t oplen = 5) {
  return RIP + static_cast<std::int32_t>(rel) + oplen;
}

/**
 * @brief Flushes CPU Instruction cache
 * @param ptr pointer to instructions
 * @param size size, in bytes
 * @return was the operation successful
 */
inline bool flush_instruction_cache(const void* ptr, std::size_t size) {
#ifdef _WIN32
  return FlushInstructionCache(GetCurrentProcess(), ptr, size) != 0;
#else
  return true;
#endif // #ifdef _WIN32
}

/**
 * @brief Checks whether the memory region at the address is executable
 * @param addr address to check
 * @return is memory region at the address is executable
 */
inline bool check_is_executable(const void* addr) {
#ifdef _WIN32
  MEMORY_BASIC_INFORMATION buffer;
  VirtualQuery(addr, &buffer, sizeof(buffer));
  return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ ||
         buffer.Protect == PAGE_EXECUTE_READWRITE || buffer.Protect == PAGE_EXECUTE_WRITECOPY;
#else

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
#endif // #ifdef _WIN32
}

enum class MemoryProt {
  PROTECT_RW,
  PROTECT_RWE,
  PROTECT_RE,
};

/**
 * @brief Sets memory region protection
 * @param addr address of the region(may be unaligned to page boundary)
 * @param size count, in bytes
 * @param protectMode new protection mode
 * @return was the operation successful
 */
inline bool set_memory_prot(const void* addr, std::size_t size, MemoryProt protectMode) {
#if defined(_WIN32)
  const DWORD c_rw = PAGE_READWRITE;
  const DWORD c_rwe = PAGE_EXECUTE_READWRITE;
  const DWORD c_re = PAGE_EXECUTE_READ;
  DWORD mode;
#else
  const int c_rw = PROT_READ | PROT_WRITE;
  const int c_rwe = PROT_READ | PROT_WRITE | PROT_EXEC;
  const int c_re = PROT_READ | PROT_EXEC;
  int mode;
#endif
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
#if defined(_WIN32)
  DWORD oldProtect;
  return VirtualProtect(const_cast<void*>(addr), size, mode, &oldProtect) != 0;
#elif defined(__GNUC__)
  size_t pageSize = sysconf(_SC_PAGESIZE);
  size_t iaddr = reinterpret_cast<size_t>(addr);
  size_t roundAddr = iaddr & ~(pageSize - static_cast<size_t>(1));
  return mprotect(reinterpret_cast<void*>(roundAddr), size + (iaddr - roundAddr), mode) == 0;
#else
  return true;
#endif
}

inline MemoryProt get_memory_prot(const void* addr) {
#ifdef _WIN32
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
#else

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
#endif
}

#if defined(_WIN32)
struct frozen_threads {
  std::vector<DWORD> thread_ids;
};
#elif defined(__linux__)
struct frozen_threads {
    struct sigaction oldact1, oldact2;
    std::vector<int> thread_ids;
};
#else
struct frozen_threads {
};
#endif

/**
 * @brief Suspends all threads except current thread
 * @param threads intermediate storage
 * @return was the operation successful
 */
inline bool freeze_threads(frozen_threads& threads) {
#if defined(_WIN32)
  auto enumerate_threads = [](frozen_threads& threads) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    auto self_tid = GetCurrentThreadId();
    auto self_pid = GetCurrentProcessId();
    auto offset = FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD);

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te)) {
      do {
        if (te.dwSize >= offset && te.th32OwnerProcessID == self_pid && te.th32ThreadID != self_tid) {
          threads.thread_ids.push_back(te.th32ThreadID);
        }
        te.dwSize = sizeof(THREADENTRY32);
      } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return true;
  };

  if (!enumerate_threads(threads)) {
    return false;
  }
  for (auto tid : threads.thread_ids) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT, FALSE, tid);
    if (hThread != NULL) {
      SuspendThread(hThread);
      CloseHandle(hThread);
    }
  }
#elif defined(__linux__)
  auto signal_callback = [](int signal) {
    switch (signal) {
      case SIGUSR1:
        pause();
      break;
      case SIGUSR2:
        break;
    }
  };

  struct sigaction act;
  if (sigemptyset(&act.sa_mask) != 0) {
    return false;
  }
  act.sa_flags = 0;
  act.sa_handler = signal_callback;

  if (sigaction(SIGUSR1, &act, &threads.oldact1) != 0) {
    return false;
  }
  if (sigaction(SIGUSR2, &act, &threads.oldact2) != 0) {
    return false;
  }

  auto self_pid = getpid();
  auto self_tid = syscall(sys_gettid);

  for (const auto& dir_entry : std::filesystem::directory_iterator{"/proc/self/task"}) {
    if (dir_entry.is_directory()) {
      auto tid_str = dir_entry.path().stem().string();
      int tid;
      std::from_chars(tid_str.c_str(), tid_str.c_str() + tid_str.size(), tid);

      if (tid != self_tid) {
        syscall(sys_tgkill, self_pid, tid, SIGUSR1);
        threads.thread_ids.push_back(tid);
      }
    }
  }
#else
  struct frozen_threads {
  };
#endif
  return true;
}

/**
 * @brief Resumes all threads previously suspended
 * @param threads parameter passed to freeze_threads
 * @return was the operation successful
 */
inline bool unfreeze_threads(frozen_threads& threads) {
#if defined(_WIN32)
  for (auto tid : threads.thread_ids) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT, FALSE, tid);
    if (hThread != NULL) {
      ResumeThread(hThread);
      CloseHandle(hThread);
    }
  }
#elif defined(__linux__)
  auto self_pid = getpid();

  for (auto tid : threads.thread_ids) {
    syscall(sys_tgkill, self_pid, tid, SIGUSR2);
  }

  sigaction(SIGUSR1, &threads.oldact1, nullptr);
  sigaction(SIGUSR2, &threads.oldact2, nullptr);
#else // #elif defined(__linux__)
  struct frozen_threads {
  };
#endif // #if defined(_WIN32)
  return true;
}

inline std::size_t detect_hook_size(std::uintptr_t addr) {
  size_t size = 0;
  while (size < 5) {
    detail::hde op;
    hde_disasm(reinterpret_cast<void*>(addr), &op);
    size += op.len;
    addr += op.len;
  }
  return size;
}

inline bool check_short_jmp_possibility(std::uintptr_t addr) {
  
}

template<typename Function>
class scope_exit {
public:
    scope_exit(Function f) : finalizer(std::move(f)) {}
    ~scope_exit() { finalizer(); }
private:
    Function finalizer;
};

inline struct JumpAllocator : Xbyak::Allocator {
  uint8_t* alloc(size_t size) override {
    void* ptr = Xbyak::AlignedMalloc(size, Xbyak::inner::ALIGN_PAGE_SIZE);
    utils::set_memory_prot(ptr, size, utils::MemoryProt::PROTECT_RWE);
    return reinterpret_cast<uint8_t*>(ptr);
  }

  void free(uint8_t* p) override {
  }

  bool useProtect() const override { return false; }
} default_jmp_allocator;
}
#endif // #ifndef KTHOOK_X86_64_UTILS_HPP_
