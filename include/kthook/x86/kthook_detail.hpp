#ifndef KTHOOK_DETAIL_HPP_
#define KTHOOK_DETAIL_HPP_

#ifdef __GNUC__
#define CCDECL __attribute__((cdecl))
#define CFASTCALL __attribute__((fastcall))
#define CSTDCALL __attribute__((stdcall))
#define CTHISCALL __attribute__((thiscall))
#else
#define CCDECL __cdecl
#define CFASTCALL __fastcall
#define CSTDCALL __stdcall
#define CTHISCALL __thiscall
#endif  // __GNUC__

namespace kthook {
namespace detail {
namespace traits {

enum class cconv {
    ccdecl,
    cfastcall,
    cthiscall,
    cstdcall,
};

template <cconv Conv, typename Ret, typename Tuple>
struct function_connect_ptr;

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::ccdecl, Ret, std::tuple<Args...>> {
    using type = Ret(CCDECL*)(Args ...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cstdcall, Ret, std::tuple<Args...>> {
    using type = Ret(CSTDCALL*)(Args ...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cthiscall, Ret, std::tuple<Args...>> {
    using type = Ret(CTHISCALL*)(Args ...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cfastcall, Ret, std::tuple<Args...>> {
    using type = Ret(CFASTCALL*)(Args ...);
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
#ifdef _WIN32
    static constexpr auto convention = cconv::cthiscall;
#else
    static constexpr auto convention = cconv::ccdecl;
#endif
    using args = std::tuple<Class*, Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CCDECL *)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    static constexpr auto convention = cconv::ccdecl;
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    static constexpr auto convention = cconv::cstdcall;
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CTHISCALL *)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    static constexpr auto convention = cconv::cthiscall;
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CSTDCALL *)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    static constexpr auto convention = cconv::cstdcall;
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CFASTCALL *)(Args ...)> {
    static constexpr auto args_count = sizeof...(Args);
    static constexpr auto convention = cconv::cfastcall;
    using args = std::tuple<Args...>;
    using return_type = Ret;
};

template <cconv Conv>
struct get_registers_count {
    static constexpr auto value = 0;
};

template <>
struct get_registers_count<cconv::cfastcall> {
    static constexpr auto value = 2;
};

template <>
struct get_registers_count<cconv::cthiscall> {
    static constexpr auto value = 1;
};

template <cconv Conv, typename Ret, typename... Args>
using function_connect_ptr_t = typename function_connect_ptr<Conv, Ret, Args...>::type;

template <class R, class... Types>
using function_connect_t = typename function_connect<R, Types...>::type;

template <typename T, typename... Ts>
using tuple_cat_t = typename tuple_cat<T, Ts...>::type;

template <class... Types>
using convert_refs_t = typename convert_refs<Types...>::type;
} // namespace traits

template <typename Ret>
constexpr bool is_return_value_needs_stack() {
    if constexpr (std::is_void_v<Ret>) return false;

    return (!(std::is_trivial_v<Ret> && std::is_standard_layout_v<Ret> && sizeof(Ret) <= 8));
}

template <typename HookPtrType, traits::cconv Convention, typename Ret, typename... Args>
struct signal_relay_generator;

template <typename HookPtrType, typename Ret, typename... Args>
struct signal_relay_generator<HookPtrType, traits::cconv::ccdecl, Ret, std::tuple<Args...>> {
    static Ret CCDECL relay(HookPtrType* this_hook, Args ... args) {
        using source_t = Ret(CCDECL*)(Args ...);
        return signal_relay<HookPtrType, Ret, Args...>(this_hook, args...);
    }
}; // namespace detail

template <typename HookPtrType, typename Ret, typename... Args>
struct signal_relay_generator<HookPtrType, traits::cconv::cstdcall, Ret, std::tuple<Args...>> {
    static Ret CSTDCALL relay(HookPtrType* this_hook, Args ... args) {
        using source_t = Ret(CSTDCALL*)(Args ...);
        return signal_relay<HookPtrType, Ret, Args...>(this_hook, args...);
    }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct signal_relay_generator<HookPtrType, traits::cconv::cthiscall, Ret, std::tuple<Args...>> {
    static Ret CSTDCALL relay(HookPtrType* this_hook, Args ... args) {
        return signal_relay<HookPtrType, Ret, Args...>(this_hook, args...);
    }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct signal_relay_generator<HookPtrType, traits::cconv::cfastcall, Ret, std::tuple<Args...>> {
    // fastcall uses registers for first two integral/pointer types (left->right)
    // so we can use this trick to get outr hook object from stack
    struct fastcall_trick {
        HookPtrType* ptr;
    };

    static Ret CFASTCALL relay(fastcall_trick esp4, Args ... args) {
        return signal_relay<HookPtrType, Ret, Args...>(esp4.ptr, args...);
    }
};

template <typename HookPtrType, traits::cconv Convention, typename Ret, typename Tuple>
struct relay_generator;

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, traits::cconv::ccdecl, Ret, std::tuple<Args...>> {
    static Ret CCDECL relay(HookPtrType* this_hook, Args ... args) {
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
    }
}; // namespace kthook

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, traits::cconv::cstdcall, Ret, std::tuple<Args...>> {
    static Ret CSTDCALL relay(HookPtrType* this_hook, Args ... args) {
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
    }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, traits::cconv::cthiscall, Ret, std::tuple<Args...>> {
    static Ret CSTDCALL relay(HookPtrType* this_hook, Args ... args) {
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
    }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, traits::cconv::cfastcall, Ret, std::tuple<Args...>> {
    // fastcall uses registers for first two integral/pointer types (left->right)
    // so we can use this trick to get outr hook object from stack
    struct fastcall_trick {
        HookPtrType* ptr;
    };

    static Ret CFASTCALL relay(fastcall_trick esp4, Args ... args) {
        auto this_hook = esp4.ptr;
        auto& cb = this_hook->get_callback();
        return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
    }
};
} // namespace detail
} // namespace kthook

#endif
