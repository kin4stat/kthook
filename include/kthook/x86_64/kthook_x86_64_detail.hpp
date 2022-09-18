#ifndef KTHOOK_DETAIL_X86_64_HPP_
#define KTHOOK_DETAIL_X86_64_HPP_

#ifdef KTHOOK_32
#define hde_disasm(code, hs) hde32_disasm(code, hs)
#else
#define hde_disasm(code, hs) hde64_disasm(code, hs)
#endif

namespace kthook {

template <std::size_t N>
struct take {
    static constexpr auto size = N;
    using kthook_take_tag = void;
};

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
struct add_refs {
};

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
    using type = ktsignal::ktsignal_threadsafe<void(const HookT&, std::add_lvalue_reference_t<Ts> ...)>;
};

template <class HookT, class T, typename... Ts>
struct on_after_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<void(const HookT&, T&, std::add_lvalue_reference_t<Ts> ...)>;
};

template <class HookT, class T, typename Tuple, typename Enable = void>
struct on_before_type;

template <class HookT, class T, typename... Ts>
struct on_before_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<bool(const HookT&, std::add_lvalue_reference_t<Ts> ...)>;
};

template <class HookT, class T, typename... Ts>
struct on_before_type<HookT, T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
    using type = ktsignal::ktsignal_threadsafe<std::optional<T>(const HookT&, std::add_lvalue_reference_t<Ts> ...)>;
};

template <typename HookType, typename Ret, typename Args>
using on_before_t = typename on_before_type<HookType, Ret, Args>::type;
template <typename HookType, typename Ret, typename Args>
using on_after_t = typename on_after_type<HookType, Ret, Args>::type;

template <typename Ret, typename... Args>
struct ft {
    using ret = Ret;
    using args = std::tuple<Args...>;
};

template <typename T>
struct cpp_function_traits;

template <typename T, typename C>
struct cpp_function_traits<T C::*> : cpp_function_traits<T> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...)> : ft<Ret, Args...> {
};

// specialization for variadic functions such as std::printf
template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...)> : ft<Ret, Args...> {
};

// specialization for function types that have cv-qualifiers
template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile> : ft<Ret, Args...> {
};

// specialization for function types that have ref-qualifiers
template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile &> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile &&> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile &&> : ft<Ret, Args...> {
};

// specializations for noexcept versions of all the above (C++17 and later)

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile & noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) volatile && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ...) const volatile && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) volatile && noexcept> : ft<Ret, Args...> {
};

template <typename Ret, typename... Args>
struct cpp_function_traits<Ret(Args ..., ...) const volatile && noexcept> : ft<Ret, Args...> {
};

template <typename T>
using ret = typename cpp_function_traits<T>::ret;

template <typename T>
using args = typename cpp_function_traits<T>::args;
} // namespace traits

template <class, class = void>
struct is_take : std::false_type {
};

template <class T>
struct is_take<T, std::void_t<typename std::remove_reference_t<T>::kthook_take_tag>> : std::true_type {
};

template <typename Tuple>
struct take_impl : take<std::tuple_size_v<Tuple>> {
    Tuple value;

    explicit take_impl(Tuple value)
        : value(std::move(value)) {
    }
};

template <bool is_take, typename T>
struct get_size {
    static constexpr auto value = 1;
};

template <typename T>
struct get_size<true, T> {
    static constexpr auto value = T::size;
};

template <typename Output, std::size_t Start, std::size_t... Is>
constexpr std::size_t count_idx_impl(std::index_sequence<Is...>) {
    return (get_size<is_take<std::tuple_element_t<Is, Output>>::value, std::remove_reference_t<std::tuple_element_t<
                         Is, Output>>>::value + ... + 0);
}

template <typename Output, std::size_t Start>
constexpr std::size_t count_idx() {
    return count_idx_impl<Output, Start>(std::make_index_sequence<Start>{});
}

template <typename Input, typename Output, std::size_t Start, std::size_t... Is>
constexpr decltype(auto) bind_impl(Input& input, std::index_sequence<Is...>) {
    return take_impl{
        std::forward_as_tuple(static_cast<
                std::tuple_element_t<
                    count_idx<Output, Start>() + Is,
                    std::remove_cv_t<std::remove_reference_t<decltype(input)>>
                >>(std::get<count_idx<Output, Start>() + Is>(input))...
            )
    };
}

template <typename Input, typename Output, std::size_t Start>
constexpr decltype(auto) bind(Input& input) {
    using output_type = std::remove_reference_t<std::tuple_element_t<Start, Output>>;
    if constexpr (is_take<output_type>::value) {
        return bind_impl<Input, Output, Start>(input, std::make_index_sequence<output_type::size>{});
    } else {
        return static_cast<
            std::tuple_element_t<
                count_idx<Output, Start>(),
                std::remove_cv_t<std::remove_reference_t<decltype(input)>>
            >>(std::get<count_idx<Output, Start>()>(input));
    }
}

template <typename Output, typename Input, std::size_t... Is>
constexpr decltype(auto) bind_values_impl(Input& input, std::index_sequence<Is...>) {
    return std::forward_as_tuple(bind<Input, Output, Is>(input)...);
}

template <typename Output, typename Input>
constexpr decltype(auto) bind_values(Input input) {
    return bind_values_impl<Output, Input>(input, std::make_index_sequence<std::tuple_size_v<Output>>{});
}

template <typename Input, std::size_t Start, typename>
struct get_types {
};

template <typename Input, std::size_t Start, std::size_t... Is>
struct get_types<Input, Start, std::index_sequence<Is...>> {
    using type = std::tuple<std::tuple_element_t<Start + Is, Input>...>;
};

template <typename Input, std::size_t Start, typename Output>
constexpr decltype(auto) unpack_impl(Output& output) {
    using output_type = std::tuple_element_t<Start, Output>;
    if constexpr (is_take<output_type>::value) {
        using tuple_type = typename get_types<Input, count_idx<Output, Start>(), std::make_index_sequence<
                                                  std::remove_reference_t<output_type>::size>>::type;
        return static_cast<take_impl<tuple_type>&&>(std::get<Start>(output)).value;
    } else {
        return std::forward_as_tuple(
            static_cast<std::tuple_element_t<Start, std::remove_cv_t<std::remove_reference_t<decltype(output)>>>>(
                std::get<Start>(output)));
    }
}

template <typename Input, typename Output, std::size_t... Is>
constexpr decltype(auto) unpack(Output output, std::index_sequence<Is...>) {
    return std::tuple_cat(unpack_impl<Input, Is>(output)...);
}

template <typename Input, typename... Ts>
constexpr decltype(auto) unpack(Ts&&... args) {
    return unpack<Input>(std::forward_as_tuple(std::forward<Ts>(args)...), std::make_index_sequence<sizeof...(Ts)>{});
}

// https://github.com/TsudaKageyu/minhook/blob/master/src/trampoline.h
#pragma pack(push, 1)
struct JCC_ABS {
    std::uint8_t opcode; // 7* 0E:         J** +16
    std::uint8_t dummy0;
    std::uint8_t dummy1; // FF25 00000000: JMP [+6]
    std::uint8_t dummy2;
    std::uint32_t dummy3;
    std::uint64_t address; // Absolute destination address
};

struct CALL_ABS {
    std::uint8_t opcode0; // FF15 00000002: CALL [+6]
    std::uint8_t opcode1;
    std::uint32_t dummy0;
    std::uint8_t dummy1; // EB 08:         JMP +10
    std::uint8_t dummy2;
    std::uint64_t address; // Absolute destination address
};

struct JMP_ABS {
    std::uint8_t opcode0; // FF25 00000000: JMP [+6]
    std::uint8_t opcode1;
    std::uint32_t dummy;
    std::uint64_t address; // Absolute destination address
};

typedef struct {
    std::uint8_t opcode;   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    std::uint32_t operand; // Relative destination address
} JMP_REL, CALL_REL;

struct JCC_REL {
    std::uint8_t opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
    std::uint8_t opcode1;
    std::uint32_t operand; // Relative destination address
};
#pragma pack(pop)

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
        std::optional<Ret> value;
        for (std::optional<Ret> return_value : before_iterate) {
            bool has_value = return_value.has_value();
            dont_skip_original &= !has_value;
            if (has_value) {
                value = std::move(return_value.value());
            }
        }
        if (dont_skip_original) {
            value = std::move(this_hook->get_trampoline()(args...));
            this_hook->after.emit(*this_hook, value.value(), args...);
        }
        return value.value();
    }
}

template <typename CallbackT, typename HookPtrType, typename Ret, typename... Args>
inline Ret common_relay(CallbackT& cb, HookPtrType* this_hook, Args&... args) {
    if (cb)
        return cb(*this_hook, args...);
    else
        return this_hook->get_trampoline()(args...);
}

template <typename HookType>
#ifdef KTHOOK_32
#ifndef __GNUC__
std::uintptr_t __cdecl
#else
__attribute__((cdecl))  std::uintptr_t
#endif
#else
std::uintptr_t
#endif
naked_relay(HookType* this_hook) {
    auto ret_addr = this_hook->get_return_address();

    auto& cb = this_hook->get_callback();
    if (cb) {
        cb(*this_hook);
    }
    if (ret_addr != this_hook->get_return_address()) {
        ret_addr = this_hook->get_return_address();
        auto hook_addr = this_hook->info.hook_address;
        auto hook_size = this_hook->hook_size;
        auto& original = this_hook->info.original_code;
        if (ret_addr > hook_addr && ret_addr - hook_addr <= hook_size) {
            std::uintptr_t result{};
            auto m = (ret_addr - hook_addr < hook_size) ? ret_addr - hook_addr : hook_size;
            for (auto i = 0u; i < m;) {
                hde hs;
                std::size_t op_size = hde_disasm(original.get() + i, &hs);
                if (hs.flags & F_ERROR) return 0;
                if (((hs.opcode & 0xF0) == 0x70) || // one byte jump
                    ((hs.opcode & 0xFC) == 0xE0) || // LOOPNZ/LOOPZ/LOOP/JECXZ
                    ((hs.opcode2 & 0xF0) == 0x80)) {
                    result += sizeof(JCC_REL);
                }
                else if ((hs.opcode & 0xFD) == 0xE9) {
                    result += sizeof(JMP_REL);
                }
                else if (hs.opcode == 0xE8) {
                    result += sizeof(JMP_REL);
                }
                else {
                    result += op_size;
                }
                i += op_size;
            }
            // if need to get into trampoline
            return result;
        } else {
            return ~0u;
        }
    }
    // if need to get into trampoline
    return 0;
}

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
#endif
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
#endif
        
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
#endif

inline bool check_is_executable(const void* addr) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION buffer;
    VirtualQuery(addr, &buffer, sizeof(buffer));
    return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ ||
           buffer.Protect == PAGE_EXECUTE_READWRITE || buffer.Protect == PAGE_EXECUTE_WRITECOPY;
#else

    auto map_infos = parse_proc_maps();

    std::uintptr_t iaddr = reinterpret_cast<std::uintptr_t>(addr);

    for (auto& mi : map_infos) {
        if (mi.start <= iaddr && iaddr < mi.end) {
            if (mi.prot & PROT_EXEC) {
                return true;
            }
        }
    }

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
    auto self_tid = gettid();

    for (const auto& dir_entry : std::filesystem::directory_iterator{"/proc/self/task"}) {
        if (dir_entry.is_directory()) {
            auto tid_str = dir_entry.path().stem().string();
            int tid;
            std::from_chars(tid_str.c_str(), tid_str.c_str() + tid_str.size(), tid);

            if (tid != self_tid) {
                tgkill(self_pid, tid, SIGUSR1);
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
        tgkill(self_pid, tid, SIGUSR2);
    }

    sigaction(SIGUSR1, &threads.oldact1, nullptr);
    sigaction(SIGUSR2, &threads.oldact2, nullptr);
#else
    struct frozen_threads {
    };
#endif
    return true;
}

inline struct JumpAllocator : Xbyak::Allocator {
    uint8_t* alloc(size_t size) override {
        void* ptr = Xbyak::AlignedMalloc(size, Xbyak::inner::ALIGN_PAGE_SIZE);
        set_memory_prot(ptr, size, MemoryProt::PROTECT_RWE);
        return reinterpret_cast<uint8_t*>(ptr);
    }

    void free(uint8_t* p) override {
    }

    bool useProtect() const override { return false; }
} default_jmp_allocator;

inline struct TrampolineAllocator : Xbyak::Allocator {
    uint8_t* alloc(size_t size) override {
        void* ptr = Xbyak::AlignedMalloc(size, Xbyak::inner::ALIGN_PAGE_SIZE);
        set_memory_prot(ptr, size, MemoryProt::PROTECT_RWE);
        return reinterpret_cast<uint8_t*>(ptr);
    }

    void free(uint8_t* p) override { Xbyak::AlignedFree(p); }
    bool useProtect() const override { return false; }
} default_trampoline_allocator;
} // namespace detail
} // namespace kthook

#endif  // KTHOOK_DETAIL_X86_64_HPP_
