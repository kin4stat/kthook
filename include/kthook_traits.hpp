#ifndef KTHOOK_TRAITS_HPP_
#define KTHOOK_TRAITS_HPP_
#include <optional>
#ifdef KTHOOK_32
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
#endif // __GNUC__
namespace kthook {
    namespace detail {
        template <typename T>
        struct return_value {
            static return_value make_true() {
                return return_value{ true, std::nullopt };
            }

            static return_value make_false(T&& value) {
                return return_value{ false, std::make_optional(value) };
            }

            bool dont_skip;
            std::optional<T> ret_val;
        };
    }
}
#endif // x32
#endif // KTHOOK_TRAITS_HPP_