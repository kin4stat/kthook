#ifndef KTHOOK_DETAIL_HPP_
#define KTHOOK_DETAIL_HPP_

namespace kthook {

    namespace hook_type_traits
    {
        enum class cconv {
            ccdecl,
            cfastcall,
            cthiscall,
            cstdcall,
        };

        template <typename>
        struct function_convention {};
        template <typename Ret, typename... Args>
        struct function_convention<Ret(CCDECL*) (Args...)>
        {
            static constexpr hook_type_traits::cconv value = hook_type_traits::cconv::ccdecl;
        };
#ifdef _WIN32
        template <typename Ret, typename Class, typename... Args>
        struct function_convention<Ret(Class::*)(Args...)>
        {
            static constexpr hook_type_traits::cconv value = hook_type_traits::cconv::cthiscall;
        };
        template <typename Ret, typename... Args>
        struct function_convention<Ret(CFASTCALL*) (Args...)>
        {
            static constexpr hook_type_traits::cconv value = hook_type_traits::cconv::cfastcall;
        };
        template <typename Ret, typename... Args>
        struct function_convention<Ret(CTHISCALL*) (Args...)>
        {
            static constexpr hook_type_traits::cconv value = hook_type_traits::cconv::cthiscall;
        };
        template <typename Ret, typename... Args>
        struct function_convention<Ret(CSTDCALL*) (Args...)>
        {
            static constexpr hook_type_traits::cconv value = hook_type_traits::cconv::cstdcall;
        };
#endif
        template <typename Func>
        constexpr hook_type_traits::cconv function_convention_v = function_convention<Func>::value;
    };

    namespace detail {
        enum class generator_type {
            simple,
            complex,
        };
#ifdef KTHOOK_32
        template <generator_type GenType, typename HookType, hook_type_traits::cconv Convention, typename Ret, typename... Args>
        struct relay_generator;
#ifdef _WIN32
        template <generator_type GenType, typename HookType, typename Ret, typename... Args>
        struct relay_generator<GenType, HookType, hook_type_traits::cconv::cstdcall, Ret, Args...> {
            static Ret CSTDCALL relay(HookType* this_hook, Args... args) {
                using SourceType = Ret(CSTDCALL*)(Args...);

                if constexpr (std::is_void_v<Ret>) {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (auto return_value : before_iterate) {
                        dont_skip_original &= return_value;
                    }
                    reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                    this_hook->after.emit(args...);
                    return;
                }
                else {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    Ret ret_value;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (detail::return_value<Ret> callback_ret : before_iterate) {
                        dont_skip_original &= callback_ret.dont_skip;
                        if (!callback_ret.dont_skip) {
                            ret_value = callback_ret.ret_val.value();
                        }
                    }
                    if (dont_skip_original) {
                        ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                    return ret_value;
                }
            }
        };

        template <generator_type GenType, typename HookType, typename Ret, typename... Args>
        struct relay_generator<GenType, HookType, hook_type_traits::cconv::cthiscall, Ret, Args...> {
            static Ret CSTDCALL relay(HookType* this_hook, Args... args) {
                using SourceType = Ret(CTHISCALL*)(Args...);

                if constexpr (std::is_void_v<Ret>) {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (auto return_value : before_iterate) {
                        dont_skip_original &= return_value;
                    }
                    reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                    this_hook->after.emit(args...);
                    return;
                }
                else {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    Ret ret_value;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (detail::return_value<Ret> callback_ret : before_iterate) {
                        dont_skip_original &= callback_ret.dont_skip;
                        if (!callback_ret.dont_skip) {
                            ret_value = callback_ret.ret_val.value();
                        }
                    }
                    if (dont_skip_original) {
                        ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                    return ret_value;
                }
            }
        };

        template <generator_type GenType, typename HookType, typename Ret, typename... Args>
        struct relay_generator<GenType, HookType, hook_type_traits::cconv::cfastcall, Ret, Args...> {

            // fastcall uses registers for first two integral/pointer types (left->right)
            // so we can use this trick to get outr hook object from stack
            struct fastcall_trick {
                HookType* ptr;
            };

            static Ret CFASTCALL relay(fastcall_trick esp4, Args... args) {
                using SourceType = Ret(CFASTCALL*)(Args...);

                HookType* this_hook = esp4.ptr;
                if constexpr (std::is_void_v<Ret>) {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (auto return_value : before_iterate) {
                        dont_skip_original &= return_value;
                    }
                    reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                    this_hook->after.emit(args...);
                    return;
                }
                else {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    Ret ret_value;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (detail::return_value<Ret> callback_ret : before_iterate) {
                        dont_skip_original &= callback_ret.dont_skip;
                        if (!callback_ret.dont_skip) {
                            ret_value = callback_ret.ret_val.value();
                        }
                    }
                    if (dont_skip_original) {
                        ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                    return ret_value;
                }
            }
        };
#endif // _WiN32
        template <generator_type GenType, typename HookType, typename Ret, typename... Args>
        struct relay_generator<GenType, HookType, hook_type_traits::cconv::ccdecl, Ret, Args...> {
            static Ret CCDECL relay(HookType* this_hook, std::uintptr_t retaddr, Args... args) {
                using SourceType = Ret(CCDECL*)(Args...);

                if constexpr (std::is_void_v<Ret>) {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (auto return_value : before_iterate) {
                        dont_skip_original &= return_value;
                    }
                    reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                    this_hook->after.emit(args...);
                    return;
                }
                else {
                    auto before_iterate = this_hook->before.emit_iterate(args...);
                    bool dont_skip_original = true;
                    Ret ret_value;
                    if constexpr (GenType == generator_type::complex) {
                        for (bool callback_ret : this_hook->before_simple.emit_iterate(args...)) {
                            dont_skip_original &= callback_ret;
                        }
                    }
                    for (detail::return_value<Ret> callback_ret : before_iterate) {
                        dont_skip_original &= callback_ret.dont_skip;
                        if (!callback_ret.dont_skip) {
                            ret_value = callback_ret.ret_val.value();
                        }
                    }
                    if (dont_skip_original) {
                        ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                    return ret_value;
                }
            }
        };
#endif // KTHOOK_32
#ifdef KTHOOK_32
        template <typename HookType, hook_type_traits::cconv Convention, typename Ret, typename... Args>
        struct relay_simple_generator;
#ifdef _WIN32
        template <typename HookType, typename Ret, typename... Args>
        struct relay_simple_generator<HookType, hook_type_traits::cconv::cstdcall, Ret, Args...> {
            static Ret CSTDCALL relay(HookType* this_hook, Args... args) {
                using SourceType = Ret(CSTDCALL*)(Args...);

                auto before_iterate = this_hook->before.emit_iterate(args...);
                bool dont_skip_original = true;
                for (auto return_value : before_iterate) {
                    dont_skip_original &= return_value;
                }
                if (dont_skip_original) {
                    if constexpr (std::is_void_v<Ret>) {
                        reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                        this_hook->after.emit(args...);
                        return;
                    }
                    else {
                        Ret ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                }
                if constexpr (!std::is_void_v<Ret>)
                    return Ret{};
            }
        };

        template <typename HookType, typename Ret, typename... Args>
        struct relay_simple_generator<HookType, hook_type_traits::cconv::cthiscall, Ret, Args...> {
            static Ret CSTDCALL relay(HookType* this_hook, Args... args) {
                using SourceType = Ret(CTHISCALL*)(Args...);

                auto before_iterate = this_hook->before.emit_iterate(args...);
                bool dont_skip_original = true;
                for (auto return_value : before_iterate) {
                    dont_skip_original &= return_value;
                }
                if (dont_skip_original) {
                    if constexpr (std::is_void_v<Ret>) {
                        reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                        this_hook->after.emit(args...);
                        return;
                    }
                    else {
                        Ret ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                }
                if constexpr (!std::is_void_v<Ret>)
                    return Ret{};
            }
        };

        template <typename HookType, typename Ret, typename... Args>
        struct relay_simple_generator<HookType, hook_type_traits::cconv::cfastcall, Ret, Args...> {

            // fastcall uses registers for first two integral/pointer types (left->right)
            // so we can use this trick to get outr hook object from stack
            struct fastcall_trick {
                HookType* ptr;
            };

            static Ret CFASTCALL relay(fastcall_trick esp4, Args... args) {
                using SourceType = Ret(CFASTCALL*)(Args...);

                HookType* this_hook = esp4.ptr;
                auto before_iterate = this_hook->before.emit_iterate(args...);
                bool dont_skip_original = true;
                for (auto return_value : before_iterate) {
                    dont_skip_original &= return_value;
                }
                if (dont_skip_original) {
                    if constexpr (std::is_void_v<Ret>) {
                        reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                        this_hook->after.emit(args...);
                        return;
                    }
                    else {
                        Ret ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                }
                if constexpr (!std::is_void_v<Ret>)
                    return Ret{};
            }
        };
#endif // _WiN32
        template <typename HookType, typename Ret, typename... Args>
        struct relay_simple_generator<HookType, hook_type_traits::cconv::ccdecl, Ret, Args...> {
            static Ret CCDECL relay(HookType* this_hook, std::uintptr_t retaddr, Args... args) {
                using SourceType = Ret(CCDECL*)(Args...);

                auto before_iterate = this_hook->before.emit_iterate(args...);
                bool dont_skip_original = true;
                for (auto return_value : before_iterate) {
                    dont_skip_original &= return_value;
                }
                if (dont_skip_original) {
                    if constexpr (std::is_void_v<Ret>) {
                        reinterpret_cast<SourceType>(this_hook->trampoline)(args...);
                        this_hook->after.emit(args...);
                        return;
                    }
                    else {
                        Ret ret_value = std::move(reinterpret_cast<SourceType>(this_hook->trampoline)(args...));
                        this_hook->after.emit(ret_value, args...);
                        return ret_value;
                    }
                }
                if constexpr (!std::is_void_v<Ret>)
                    return Ret{};
            }
        };
#endif // KTHOOK_32
    }
}
#endif // KTHOOK_DETAIL_HPP_