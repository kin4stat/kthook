#ifndef KTHOOK_DETAIL_HPP_
#define KTHOOK_DETAIL_HPP_
namespace kthook {
namespace detail {
namespace traits {
template <typename Ret, typename T, typename Enable = void>
struct count_integrals {};

#ifdef KTHOOK_64_WIN
template <typename Ret, typename... Ts>
struct count_integrals<Ret, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<Ret>>::type> {
    static constexpr auto value = sizeof...(Ts);
};
#else
template <typename Ret, typename... Ts>
struct count_integrals<Ret, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<Ret>>::type> {
    static constexpr auto value = (std::is_integral_v<Ts> + ... + 0) + (std::is_pointer_v<Ts> + ... + 0);
};
#endif

#ifdef KTHOOK_64_WIN
template <typename Ret, typename... Ts>
struct count_integrals<Ret, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<Ret>>::type> {
    static constexpr auto value = sizeof...(Ts) + (!(std::is_trivial_v<Ret> && std::is_standard_layout_v<Ret> &&
                                                     (sizeof(Ret) % 2 == 0) && sizeof(Ret) <= 8));
};
#else
template <typename Ret, typename... Ts>
struct count_integrals<Ret, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<Ret>>::type> {
    static constexpr auto value = (std::is_integral_v<Ts> + ... + 0) + (std::is_pointer_v<Ts> + ... + 0);
};
#endif

template <typename Ret, typename Tuple>
struct function_connect_ptr;
template <typename Ret, typename... Args>
struct function_connect_ptr<Ret, std::tuple<Args...>> {
    using type = Ret (*)(Args...);
};

template <class R, class Tuple>
struct function_connect;
template <class R, class... Types>
struct function_connect<R, std::tuple<Types...>> {
    using type = R(Types...);
};

template <typename Pointer>
struct function_traits;

template <typename Ret, typename Class, typename... Args>
struct function_traits<Ret (Class::*)(Args...)> {
    static constexpr auto args_count = sizeof...(Args);
    using args = std::tuple<Class*, Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret (*)(Args...)> {
    static constexpr auto args_count = sizeof...(Args);
    using args = std::tuple<Args...>;
    using return_type = Ret;
};
template <typename Ret, typename... Args>
struct function_traits<Ret(Args...)> {
    static constexpr auto args_count = sizeof...(Args);
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
using function_connect_ptr_t = typename function_connect_ptr<Ret, Args...>::type;

template <class R, class... Types>
using function_connect_t = typename function_connect<R, Types...>::type;

template <typename Ret, typename T>
constexpr auto count_integrals_v = count_integrals<Ret, T>::value;
}  // namespace traits

template <typename HookType, typename Ret, typename Tuple>
struct common_relay_generator {};

template <typename HookType, typename Ret, typename... Ts>
struct common_relay_generator<HookType, Ret, std::tuple<Ts...>> {
    static Ret relay(Ts... args, HookType* this_hook) {
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookType, Ret, Ts...>(cb, this_hook, args...);
    }
};

template <typename HookType, typename Ret, typename Tuple>
struct signal_relay_generator {};

template <typename HookType, typename Ret, typename... Ts>
struct signal_relay_generator<HookType, Ret, std::tuple<Ts...>> {
    static Ret relay(Ts... args, HookType* this_hook) { return signal_relay<HookType, Ret, Ts...>(this_hook, args...); }
};

inline std::uintptr_t find_prev_free(std::uintptr_t from, std::uintptr_t to, std::uintptr_t granularity) {
#ifdef KTHOOK_64_WIN
    to -= to % granularity;  // alignment
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
    to -= to % granularity;  // alignment
    to -= granularity;
    while (from < to) {
        void* alloc = mmap(reinterpret_cast<void*>(to), granularity, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0);
        if (reinterpret_cast<std::uintptr_t>(alloc) != 0xffffffffffffffff) return to;
        if (to < granularity) break;
        to = to - granularity;
    }
    return 0;
#endif
}

inline std::uintptr_t find_next_free(std::uintptr_t from, std::uintptr_t to, std::uintptr_t granularity) {
#ifdef KTHOOK_64_WIN
    from -= from % granularity;  // alignment
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
    from -= from % granularity;  // alignment
    from += granularity;
    while (from <= to) {
        void* alloc = mmap(reinterpret_cast<void*>(from), granularity, PROT_EXEC | PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0);
        if (reinterpret_cast<std::uintptr_t>(alloc) != 0xffffffffffffffff) return from;
        from += granularity - 1;
        from -= from % granularity;
    }
    return 0;
#endif
}

inline void* try_alloc_near(std::uintptr_t address) {
#ifdef KTHOOK_64_WIN
    constexpr auto kMaxMemoryRange = 0x40000000;  // 1gb
    constexpr auto kMemoryBlockSize = 0x1000;     // windows page size
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

            result = reinterpret_cast<void*>(alloc);
            break;
        }
    }
    if (result == nullptr) {
        std::uintptr_t alloc = address;
        while (alloc <= max_address) {
            alloc = find_next_free(alloc, max_address, kMemoryBlockSize);
            if (alloc == 0) break;

            result = reinterpret_cast<void*>(alloc);
        }
    }
    return result;
#endif
}
}  // namespace detail
}  // namespace kthook

#endif  // KTHOOK_DETAIL_HPP_