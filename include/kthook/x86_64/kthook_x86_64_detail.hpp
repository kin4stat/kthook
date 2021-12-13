#ifndef KTHOOK_DETAIL_X86_64_HPP_
#define KTHOOK_DETAIL_X86_64_HPP_

#ifdef KTHOOK_32
#define hde_disasm(code, hs) hde32_disasm(code, hs)
#else
#define hde_disasm(code, hs) hde64_disasm(code, hs)
#endif

namespace kthook {
namespace detail {
#ifdef KTHOOK_32
using hde = hde32s;
#else
using hde = hde64s;
#endif

namespace traits {
template <typename T, typename Enable = void>
struct convert_ref {
    using type = T;
};

template <typename T>
struct convert_ref<T, std::enable_if_t<std::is_reference_v<T>>> {
    using type = std::add_pointer_t<std::remove_cv_t<std::remove_reference_t<T>>>;
};

template <typename T>
using convert_ref_t = typename convert_ref<T>::type;

template <typename Tuple>
struct convert_refs;

template <typename... Ts>
struct convert_refs<std::tuple<Ts...>> {
    using type = std::tuple<convert_ref_t<Ts>...>;
};

template <class... Types>
using convert_refs_t = typename convert_refs<Types...>::type;

template <typename Tuple>
struct add_refs {};

template <typename... Ts>
struct add_refs<std::tuple<Ts...>> {
    using type = std::tuple<std::add_lvalue_reference_t<Ts>...>;
};

template <typename T>
using add_refs_t = typename add_refs<T>::type;

template <typename T, typename Tuple>
struct tuple_cat;

template <typename T, typename... Ts>
struct tuple_cat<T, std::tuple<Ts...>> {
    using type = std::tuple<T, Ts...>;
};

template <typename T, typename... Ts>
using tuple_cat_t = typename tuple_cat<T, Ts...>::type;

template <class HookT, class T, typename Tuple, typename Enable = void>
struct on_after_type;

template <class HookT, class T, typename... Ts>
struct on_after_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<void(const HookT&, std::add_lvalue_reference_t<Ts>...)>;
};

template <class HookT, class T, typename... Ts>
struct on_after_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<void(const HookT&, T&, std::add_lvalue_reference_t<Ts>...)>;
};

template <class HookT, class T, typename Tuple, typename Enable = void>
struct on_before_type;

template <class HookT, class T, typename... Ts>
struct on_before_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<bool(const HookT&, std::add_lvalue_reference_t<Ts>...)>;
};

template <class HookT, class T, typename... Ts>
struct on_before_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<std::optional<T>(const HookT&, std::add_lvalue_reference_t<Ts>...)>;
};

template <typename HookType, typename Ret, typename Args>
using on_before_t = typename on_before_type<HookType, Ret, Args>::type;
template <typename HookType, typename Ret, typename Args>
using on_after_t = typename on_after_type<HookType, Ret, Args>::type;
}  // namespace traits

template <typename HookPtrType, typename Ret, typename... Args>
inline Ret signal_relay(HookPtrType* this_hook, Args&... args) {
    if constexpr (std::is_void_v<Ret>) {
        auto before_iterate = this_hook->before.emit_iterate(*this_hook, args...);
        bool dont_skip_original = true;
        for (auto return_value : before_iterate) {
            dont_skip_original &= return_value;
        }
        if (dont_skip_original) {
            this_hook->get_trampoline()(args...);
            this_hook->after.emit(*this_hook, args...);
        }
        return;
    } else {
        auto before_iterate = this_hook->before.emit_iterate(*this_hook, args...);
        bool dont_skip_original = true;
        Ret value{};
        for (std::optional<Ret> return_value : before_iterate) {
            bool has_value = return_value.has_value();
            dont_skip_original &= !has_value;
            if (has_value) {
                value = return_value.value();
            }
        }
        if (dont_skip_original) {
            value = std::move(this_hook->get_trampoline()(args...));
            this_hook->after.emit(*this_hook, value, args...);
        }
        return value;
    }
}

template <typename CallbackT, typename HookPtrType, typename Ret, typename... Args>
inline Ret common_relay(CallbackT& cb, HookPtrType* this_hook, Args&... args) {
    if (cb)
        return cb(*this_hook, args...);
    else
        return this_hook->get_trampoline()(args...);
}

// https://github.com/TsudaKageyu/minhook/blob/master/src/trampoline.h
#pragma pack(push, 1)
struct JCC_ABS {
    std::uint8_t opcode;  // 7* 0E:         J** +16
    std::uint8_t dummy0;
    std::uint8_t dummy1;  // FF25 00000000: JMP [+6]
    std::uint8_t dummy2;
    std::uint32_t dummy3;
    std::uint64_t address;  // Absolute destination address
};

struct CALL_ABS {
    std::uint8_t opcode0;  // FF15 00000002: CALL [+6]
    std::uint8_t opcode1;
    std::uint32_t dummy0;
    std::uint8_t dummy1;  // EB 08:         JMP +10
    std::uint8_t dummy2;
    std::uint64_t address;  // Absolute destination address
};

struct JMP_ABS {
    std::uint8_t opcode0;  // FF25 00000000: JMP [+6]
    std::uint8_t opcode1;
    std::uint32_t dummy;
    std::uint64_t address;  // Absolute destination address
};
typedef struct {
    std::uint8_t opcode;    // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    std::uint32_t operand;  // Relative destination address
} JMP_REL, CALL_REL;

struct JCC_REL {
    std::uint8_t opcode0;  // 0F8* xxxxxxxx: J** +6+xxxxxxxx
    std::uint8_t opcode1;
    std::uint32_t operand;  // Relative destination address
};
#pragma pack(pop)

inline std::size_t detect_hook_size(std::uintptr_t addr) {
    size_t size = 0;
    while (size < 5) {
        hde op;
        hde_disasm(reinterpret_cast<void*>(addr), &op);
        size += op.len;
        addr += op.len;
    }
    return size;
}

inline std::uintptr_t get_relative_address(std::uintptr_t dest, std::uintptr_t src, std::size_t oplen = 5) {
    return dest - src - oplen;
}
inline std::uintptr_t restore_absolute_address(std::uintptr_t RIP, std::uintptr_t rel, std::size_t oplen = 5) {
    return RIP + static_cast<std::int32_t>(rel) + oplen;
}

inline bool flush_intruction_cache(const void* ptr, std::size_t size) {
#ifdef _WIN32
    return FlushInstructionCache(GetCurrentProcess(), ptr, size) != 0;
#else
    return true;
    // return cacheflush(ptr, size, ICACHE) == 0;
#endif
}

inline bool check_is_executable(const void* addr) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION buffer;
    VirtualQuery(addr, &buffer, sizeof(buffer));
    return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ ||
           buffer.Protect == PAGE_EXECUTE_READWRITE;
#else
    // POSIX HACK PON PON
    static auto granularity = sysconf(_SC_PAGESIZE);
    void* allocated = mmap(const_cast<void*>(addr), granularity, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0);
    if (reinterpret_cast<std::uintptr_t>(alloc) == 0xffffffffffffffff) return true;
    munmap(const_cast<void*>(addr), granularity);
    return false;
#endif
}

enum class MemoryProt {
    PROTECT_RW,
    PROTECT_RWE,
    PROTECT_RE,
};
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
struct JumpAllocator : Xbyak::Allocator {
    virtual uint8_t* alloc(size_t size) {
        void* ptr = Xbyak::AlignedMalloc(size, Xbyak::inner::ALIGN_PAGE_SIZE);
        set_memory_prot(ptr, size, MemoryProt::PROTECT_RWE);
        return reinterpret_cast<uint8_t*>(ptr);
    }
    virtual void free(uint8_t* p) { }
    virtual bool useProtect() const { return false; }
} default_jmp_allocator;
}  // namespace detail
}  // namespace kthook

#endif  // KTHOOK_DETAIL_X86_64_HPP_