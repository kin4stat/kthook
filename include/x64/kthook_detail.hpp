#ifndef KTHOOK_DETAIL_HPP_
#define KTHOOK_DETAIL_HPP_

namespace kthook {
namespace detail {
namespace traits {
template <typename Ret, typename T, typename Enable = void>
struct count_integrals {
};

struct relay_args_info {
    std::size_t head_size;
    std::size_t tail_size;
    int register_idx_if_full = -1; // if -1 then register don't used
};

#ifdef _WIN32
template <typename Ret, typename... Ts>
constexpr relay_args_info internal_get_head_and_tail_size(std::size_t integral_registers_count) {
    relay_args_info result{};
    std::size_t used_integral_registers = sizeof...(Ts);
    bool used = false;
    if constexpr (!std::is_void_v<Ret>) {
        auto res =
            (!(std::is_trivial_v<Ret> && std::is_standard_layout_v<Ret> && (sizeof(Ret) % 2 == 0 || sizeof(Ret) == 1) && sizeof(Ret) <= 8));
        if (res) used = true;
        used_integral_registers += res;
    }
    if (used_integral_registers >= integral_registers_count) {
        if (used)
            result.head_size = integral_registers_count - 1;
        else
            result.head_size = integral_registers_count;
        result.tail_size = sizeof...(Ts) - result.head_size;
    } else {
        if (used)
            result.head_size = used_integral_registers - 1;
        else
            result.head_size = used_integral_registers;
        result.tail_size = 0;
        result.register_idx_if_full = static_cast<int>(used_integral_registers);
    }
    return result;
}
#else
template <typename Ret, typename... Ts>
constexpr relay_args_info internal_get_head_and_tail_size(std::size_t integral_registers_count) {
    return {0, sizeof...(Ts), -1};
}
#endif

template <std::size_t RegistersCount, typename Ret, typename Tuple>
struct get_head_and_tail_size {
};

template <std::size_t RegistersCount, typename Ret, typename... Ts>
struct get_head_and_tail_size<RegistersCount, Ret, std::tuple<Ts...>> {
    static constexpr auto value = internal_get_head_and_tail_size<Ret, Ts...>(RegistersCount);
};

template <typename Tuple, typename Sequence>
struct get_first_n_types {
};

template <typename Tuple, std::size_t... Is>
struct get_first_n_types<Tuple, std::index_sequence<Is...>> {
    using type = std::tuple<std::tuple_element_t<Is, Tuple>...>;
};

template <std::size_t N, typename Tuple>
using get_first_n_types_t = typename get_first_n_types<Tuple, std::make_index_sequence<N>>::type;

template <std::size_t N, typename Tuple, typename Sequence>
struct get_last_n_types {
};

template <std::size_t N, typename Tuple, std::size_t... Is>
struct get_last_n_types<N, Tuple, std::index_sequence<Is...>> {
    using type = std::tuple<std::tuple_element_t<Is + N, Tuple>...>;
};

template <std::size_t N, typename Tuple, std::size_t TupleSize>
using get_last_n_types_t = typename get_last_n_types<TupleSize - N, Tuple, std::make_index_sequence<N>>::type;

template <typename Ret, typename Tuple>
struct function_connect_ptr;

template <typename Ret, typename... Args>
struct function_connect_ptr<Ret, std::tuple<Args...>> {
    using type = Ret (*)(Args ...);
};

template <class R, class Tuple>
struct function_connect;

template <class R, class... Types>
struct function_connect<R, std::tuple<Types...>> {
    using type = R(Types ...);
};

template <typename Pointer>
struct function_traits;

template <typename Ret, typename Class, typename... Args>
struct function_traits<Ret (Class::*)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args) + 1;
    using args = std::tuple<Class*, Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret (*)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
using function_connect_ptr_t = typename function_connect_ptr<Ret, Args...>::type;

template <class R, class... Types>
using function_connect_t = typename function_connect<R, Types...>::type;

} // namespace traits

#ifndef _WIN32
template <typename HookType>
struct SystemVAbiTrick {
    HookType* ptr;

private:
    void *junk1, *junk2, *junk3;
};

#endif

template <typename HookType, typename Ret, typename Head, typename Tail, typename Args>
struct common_relay_generator {
};

template <typename HookType, typename Ret, typename... Head, typename... Tail, typename... Args>
struct common_relay_generator<HookType, Ret, std::tuple<Head...>, std::tuple<Tail...>, std::tuple<Args...>> {
#ifndef _WIN32
    static Ret relay(Head... head_args, SystemVAbiTrick<HookType> rsp_ptr, Tail... tail_args) {
        auto this_hook = rsp_ptr.ptr;
#else
    static Ret relay(Head ... head_args, HookType* this_hook, void*, Tail ... tail_args) {
#endif
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookType, Ret, Args...>(cb, this_hook, head_args..., tail_args...);
    }
}; // namespace detail

template <typename HookType, typename Ret, typename Head, typename Tail, typename Args>
struct common_relay_generator_three_args {
};

template <typename HookType, typename Ret, typename... Head, typename... Tail, typename... Args>
struct common_relay_generator_three_args<HookType, Ret, std::tuple<Head...>, std::tuple<Tail...>, std::tuple<Args...>> {
#ifndef _WIN32
        static Ret relay(Head... head_args, SystemVAbiTrick<HookType> rsp_ptr, Tail... tail_args) {
            auto this_hook = rsp_ptr.ptr;
#else
    static Ret relay(Head ... head_args, HookType* this_hook, Tail ... tail_args) {
#endif
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookType, Ret, Args...>(cb, this_hook, head_args..., tail_args...);
    }
}; // namespace detail

template <typename HookType, typename Ret, typename Head, typename Tail, typename Args>
struct signal_relay_generator {
};

template <typename HookType, typename Ret, typename... Head, typename... Tail, typename... Args>
struct signal_relay_generator<HookType, Ret, std::tuple<Head...>, std::tuple<Tail...>, std::tuple<Args...>> {
#ifndef _WIN32
    static Ret relay(Head... head_args, SystemVAbiTrick<HookType> rsp_ptr, Tail... tail_args) {
        auto this_hook = rsp_ptr.ptr;
#else
    static Ret relay(Head ... head_args, HookType* this_hook, void*, Tail ... tail_args) {
#endif
        return signal_relay<HookType, Ret, Args...>(this_hook, head_args..., tail_args...);
    }
};

template <typename HookType, typename Ret, typename Head, typename Tail, typename Args>
struct signal_relay_generator_three_args;

template <typename HookType, typename Ret, typename... Head, typename... Tail, typename... Args>
struct signal_relay_generator_three_args<HookType, Ret, std::tuple<Head...>, std::tuple<Tail...>, std::tuple<Args...>> {
#ifndef _WIN32
    static Ret relay(Head... head_args, SystemVAbiTrick<HookType> rsp_ptr, Tail... tail_args) {
        auto this_hook = rsp_ptr.ptr;
#else
    static Ret relay(Head ... head_args, HookType* this_hook, Tail ... tail_args) {
#endif
        return signal_relay<HookType, Ret, Args...>(this_hook, head_args..., tail_args...);
    }
};

inline std::uintptr_t find_prev_free(std::uintptr_t from, std::uintptr_t to, std::uintptr_t granularity) {
#ifdef KTHOOK_64_WIN
    to -= to % granularity; // alignment
    to -= granularity;
    while (from < to) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<void*>(to), &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_FREE) return to;
        if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) < granularity) break;
        to = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) - granularity;
    }
    return 0;
#else
    auto map_infos = parse_proc_maps();

    to -= to % granularity;  // alignment
    to -= granularity;
    while (from < to) {
        bool found = false;
        for (auto& mi : map_infos) {
            if (mi.start <= to && to < mi.end) {
                found = true;
                to = mi.start - granularity;
                if (mi.start < granularity) {
                    return 0;
                }
                break;
            }
        }
        if (!found) {
            return to;
        }
    }
    return 0;
#endif
}

inline std::uintptr_t find_next_free(std::uintptr_t from, std::uintptr_t to, std::uintptr_t granularity) {
#ifdef KTHOOK_64_WIN
    from -= from % granularity; // alignment
    from += granularity;
    while (from <= to) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<void*>(from), &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_FREE) return from;
        if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) < granularity) break;
        from = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) + mbi.RegionSize;

        from += granularity - 1;
        from -= from % granularity;
    }
    return 0;
#else
    auto map_infos = parse_proc_maps();

    from -= from % granularity;  // alignment
    from += granularity;
    while (from <= to) {
        bool found = false;
        for (auto& mi : map_infos) {
            if (mi.start <= from && from < mi.end) {
                found = true;
                from = mi.end;
                if (mi.start < granularity) {
                    return 0;
                }
                break;
            }
        }
        if (found) {
            from += granularity - 1;
            from -= from % granularity;
        }
        else {
            return from;
        }
    }
    return 0;
#endif
}

inline void* try_alloc_near(std::uintptr_t address) {
#ifdef KTHOOK_64_WIN
    constexpr auto kMaxMemoryRange = 0x40000000; // 1gb
    constexpr auto kMemoryBlockSize = 0x1000;    // windows page size
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    std::uintptr_t min_address = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    std::uintptr_t max_address = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

    if (kMaxMemoryRange <= address && min_address < address - kMaxMemoryRange) min_address = address - kMaxMemoryRange;

    if (address + kMaxMemoryRange <= max_address) max_address = address + kMaxMemoryRange;

    // Make room for one page
    max_address -= kMemoryBlockSize - 1;

    void* result = nullptr;
    {
        std::uintptr_t alloc = address;
        while (min_address <= alloc) {
            alloc = find_prev_free(min_address, alloc, si.dwAllocationGranularity);
            if (alloc == 0) break;

            result = VirtualAlloc(reinterpret_cast<void*>(alloc), kMemoryBlockSize, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
            if (result != nullptr) break;
        }
    }
    if (result == nullptr) {
        std::uintptr_t alloc = address;
        while (alloc <= max_address) {
            alloc = find_next_free(alloc, max_address, si.dwAllocationGranularity);
            if (alloc == 0) break;

            result = VirtualAlloc(reinterpret_cast<void*>(alloc), kMemoryBlockSize, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
            if (result != nullptr) break;
        }
    }
    return result;
#else
    constexpr auto kMaxMemoryRange = 0x40000000;  // 1gb
    static auto kMemoryBlockSize = sysconf(_SC_PAGESIZE);

    std::uintptr_t min_address = address;
    std::uintptr_t max_address = address;

    if (kMaxMemoryRange <= address) min_address = address - kMaxMemoryRange;

    // overflow check
    if (address < address + kMaxMemoryRange) max_address = address + kMaxMemoryRange;

    max_address -= kMemoryBlockSize - 1;
    void* result = nullptr;
    {
        std::uintptr_t alloc = address;
        while (min_address <= alloc) {
            alloc = find_prev_free(min_address, alloc, kMemoryBlockSize);
            if (alloc == 0) break;

            result = mmap(reinterpret_cast<void*>(alloc), kMemoryBlockSize, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
            if (result == reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFF) || reinterpret_cast<std::uintptr_t>(result) != alloc) result = nullptr;
            break;
        }
    }
    if (result == nullptr) {
        std::uintptr_t alloc = address;
        while (alloc <= max_address) {
            alloc = find_next_free(alloc, max_address, kMemoryBlockSize);
            if (alloc == 0) break;

            result = mmap(reinterpret_cast<void*>(alloc), kMemoryBlockSize, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
            if (result == reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFF) || reinterpret_cast<std::uintptr_t>(result) != alloc) result = nullptr;
            break;
        }
    }
    return result;
#endif
}
} // namespace detail
} // namespace kthook

#endif  // KTHOOK_DETAIL_HPP_
