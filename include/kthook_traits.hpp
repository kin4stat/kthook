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
#ifdef KTHOOK_64
#include "../hde/hde64.h"
        using hde = hde64s;
#define hde_disasm(code, hs) hde64_disasm(code, hs)
#else
#include "../hde/hde32.h"
        using hde = hde32s;
#define hde_disasm(code, hs) hde32_disasm(code, hs)
#endif
        // from https://github.com/TsudaKageyu/minhook/blob/master/src/trampoline.h
#pragma pack(push, 1)
#ifdef KTHOOK_64
        struct JCC_ABS
        {
            std::uint8_t  opcode;      // 7* 0E:         J** +16
            std::uint8_t  dummy0;
            std::uint8_t  dummy1;      // FF25 00000000: JMP [+6]
            std::uint8_t  dummy2;
            std::uint32_t dummy3;
            std::uint64_t address;     // Absolute destination address
        };

        struct CALL_ABS
        {
            std::uint8_t  opcode0;     // FF15 00000002: CALL [+6]
            std::uint8_t  opcode1;
            std::uint32_t dummy0;
            std::uint8_t  dummy1;      // EB 08:         JMP +10
            std::uint8_t  dummy2;
            std::uint64_t address;     // Absolute destination address
        };

        struct JMP_ABS
        {
            std::uint8_t  opcode0;     // FF25 00000000: JMP [+6]
            std::uint8_t  opcode1;
            std::uint32_t dummy;
            std::uint64_t address;     // Absolute destination address
        };
#else
        typedef struct
        {
            std::uint8_t  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
            std::uint32_t operand;     // Relative destination address
        } JMP_REL, CALL_REL;

        struct JCC_REL
        {
            std::uint8_t  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
            std::uint8_t  opcode1;
            std::uint32_t operand;     // Relative destination address
        };
#endif
#pragma pack(pop)

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