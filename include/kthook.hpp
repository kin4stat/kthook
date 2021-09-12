#ifndef KTHOOK_HPP_
#define KTHOOK_HPP_

#if defined(_WIN64) || defined(__MINGW64__) || (defined(__CYGWIN__) && defined(__x86_64__))
#define KTHOOK_64_WIN
#elif defined(__x86_64__)
#define KTHOOK_64_GCC
#endif
#if !defined(KTHOOK_64) && !defined(KTHOOK_32)
#if defined(KTHOOK_64_GCC) || defined(KTHOOK_64_WIN)
#define KTHOOK_64
#else
#define KTHOOK_32
#endif
#endif

#ifdef KTHOOK_64
#error x64 support WIP
#endif

#include "kthook_traits.hpp"
#include "kthook_detail.hpp"
#include "../xbyak/xbyak.h"
#include "../ktsignal/include/ktsignal.hpp"
#include <memory>
#include <type_traits>
#include <cstdint>
#include <cstddef>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <asm/cachectl.h>
#endif

namespace kthook {
    namespace detail {
        static inline std::size_t detect_hook_size(std::uintptr_t addr) {
            size_t size = 0;
            while (size < 5) {
                hde op;
                hde_disasm(reinterpret_cast<void*>(addr), &op);
                size += op.len;
                addr += op.len;
            }
            return size;
        }

        static inline std::uintptr_t get_relative_address(std::uintptr_t dest, std::uintptr_t src, std::size_t oplen = 5) { return dest - src - oplen; }
        static inline std::uintptr_t restore_absolute_address(std::uintptr_t RIP, std::uintptr_t rel, std::size_t oplen = 5) { return RIP + rel + oplen; }

        static inline bool flush_intruction_cache(void* ptr, std::size_t size) {
#ifdef _WIN32
            return FlushInstructionCache(GetCurrentProcess(), ptr, size) != 0;
#else
            return cacheflush(ptr, size, ICACHE) == 0;
#endif
        }

        static inline bool check_is_executable(void* addr) {
#ifdef _WIN32
            MEMORY_BASIC_INFORMATION buffer;
            VirtualQuery(addr, &buffer, sizeof(buffer));
            return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ || PAGE_EXECUTE_READWRITE;
#else
            return true;
#endif
        }

        enum class MemoryProt {
            PROTECT_RW,
            PROTECT_RWE,
            PROTECT_RE,
        };
        static inline bool set_memory_prot(const void* addr, std::size_t size, MemoryProt protectMode) {
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
            case MemoryProt::PROTECT_RW: mode = c_rw; break;
            case MemoryProt::PROTECT_RWE: mode = c_rwe; break;
            case MemoryProt::PROTECT_RE: mode = c_re; break;
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

        template <hook_type_traits::cconv Convention, typename Ret, typename... Args>
        class kthook_internal_impl {
#ifdef KTHOOK_32
            hook_type_traits::cconv hook_convention;
#endif
        public:

            kthook_internal_impl(bool force_install = true) {
                trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
                jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            }
            ~kthook_internal_impl() {
                remove();
            }

            bool install() {
                using namespace Xbyak::util;

                if (!check_is_executable(reinterpret_cast<void*>(hook_address))) return false;

                if (!create_trampoline()) return false;
                flush_intruction_cache(reinterpret_cast<void*>(trampoline), trampoline_gen->getSize());
                trampoline = const_cast<std::uint8_t*>(trampoline_gen->getCode());
                if (!patch_hook(true)) return false;
                return true;
            }
            bool remove() {
                if (!patch_hook(false)) return false;
                trampoline_gen->reset();
                jump_gen->reset();
                return true;
            }
        protected:
            std::uintptr_t hook_address;
            std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
            std::uint8_t* trampoline;
            void* relay;
        private:
            bool patch_hook(bool enable) {
                if (enable) {
                    hook_size = detail::detect_hook_size(hook_address);
                    original_code = std::make_unique<unsigned char[]>(hook_size);
                    std::memcpy(original_code.get(), reinterpret_cast<void*>(hook_address), hook_size);

                    if (!set_memory_prot(reinterpret_cast<void*>(hook_address), hook_size, MemoryProt::PROTECT_RWE)) return false;
                    if (*reinterpret_cast<std::uint8_t*>(hook_address) == 0xE8) {
                        uintptr_t relative = detail::get_relative_address(reinterpret_cast<uintptr_t>(generate_relay_jump()), hook_address);
                        *reinterpret_cast<std::uint32_t*>(hook_address + 1) = relative;
                    }
                    else {
                        uintptr_t relative = detail::get_relative_address(reinterpret_cast<uintptr_t>(generate_relay_jump()), hook_address);
                        *reinterpret_cast<std::uint8_t*>(hook_address) = 0xE9;
                        *reinterpret_cast<std::uint32_t*>(hook_address + 1) = relative;
                        memset(reinterpret_cast<void*>(hook_address + 5), 0x90, hook_size - 5);
                    }
                    if (!set_memory_prot(reinterpret_cast<void*>(hook_address), hook_size, MemoryProt::PROTECT_RE)) return false;
                }
                else {
                    if (!set_memory_prot(reinterpret_cast<void*>(hook_address), hook_size, MemoryProt::PROTECT_RWE)) return false;
                    std::memcpy(reinterpret_cast<void*>(hook_address), original_code.get(), hook_size);
                    if (!set_memory_prot(reinterpret_cast<void*>(hook_address), hook_size, MemoryProt::PROTECT_RE)) return false;
                }
                flush_intruction_cache(reinterpret_cast<void*>(hook_address), hook_size);
                return true;
            }

            bool create_trampoline()
            {
                // save original code
#ifdef KTHOOK_64
                CALL_ABS call = {
                    0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
                    0xEB, 0x08,             // EB 08:         JMP +10
                    0x0000000000000000ULL   // Absolute destination address
                };
                JMP_ABS jmp = {
                    0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
                    0x0000000000000000ULL   // Absolute destination address
                };
                JCC_ABS jcc = {
                    0x70, 0x0E,             // 7* 0E:         J** +16
                    0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
                    0x0000000000000000ULL   // Absolute destination address
                };
#else
                CALL_REL call = {
                    0xE8,                   // E8 xxxxxxxx: CALL +5+xxxxxxxx
                    0x00000000              // Relative destination address
                };
                JMP_REL jmp = {
                    0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx
                    0x00000000              // Relative destination address
                };
                JCC_REL jcc = {
                    0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
                    0x00000000              // Relative destination address
                };
#endif
                std::size_t trampoline_size = 0;
                std::size_t op_copy_size = 0;
                void* op_copy_src = nullptr;
                std::uintptr_t current_address = hook_address;
                std::uintptr_t max_jmp_ref = 0;
                bool finished = false;
#ifdef KTHOOK_64
                std::uint8_t inst_buf[16];
#endif

                while (!finished) {
                    hde hs;
                    std::size_t op_copy_size = hde_disasm(reinterpret_cast<void*>(current_address), &hs);
                    if (hs.flags & F_ERROR)
                        return false;
                    op_copy_src = reinterpret_cast<void*>(current_address);
                    if (current_address - hook_address >= sizeof(JMP_REL)) {
                        trampoline_gen->jmp(reinterpret_cast<std::uint8_t*>(current_address));
                        break;
                    }
#ifdef KTHOOK_64
                    else if ((hs.modrm & 0xC7) == 0x05)
                    {
                        // Instructions using RIP relative addressing. (ModR/M = 00???101B)

                        // Modify the RIP relative address.
                        std::uint32_t* pRelAddr;

                        std::memcpy(inst_buf, reinterpret_cast<void*>(current_address), op_copy_size);

                        op_copy_src = inst_buf;

                        // Relative address is stored at (instruction length - immediate value length - 4).
                        pRelAddr = reinterpret_cast<std::uint32_t*>(inst_buf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
                        *pRelAddr = reinterpret_cast<std::uint32_t>((current_address + hs.len + hs.disp.disp32) - (trampoline_gen->getCurr() + trampoline_size + hs.len));

                        // Complete the function if JMP (FF /4).
                        if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                            finished = true;
                    }
#endif
                    // Relative Call
                    else if (hs.opcode == 0xE8)
                    {
                        std::uintptr_t call_destination = restore_absolute_address(current_address, hs.imm.imm32, hs.len);
#if KTHOOK_64
                        call.address = call_destination;
#else
                        call.operand = get_relative_address(call_destination,
                            reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr() + trampoline_size), sizeof(call));
#endif
                        op_copy_src = &call;
                        op_copy_size = sizeof(call);
                    }
                    // Relative jmp
                    else if ((hs.opcode & 0xFD) == 0xE9)
                    {
                        std::uintptr_t jmp_destination = current_address + hs.len;

                        if (hs.opcode == 0xEB) // is short jump
                            jmp_destination += hs.imm.imm8;
                        else
                            jmp_destination += hs.imm.imm32;

                        if (hook_address <= jmp_destination
                            && jmp_destination < (hook_address + sizeof(JMP_REL)))
                        {
                            if (max_jmp_ref < jmp_destination)
                                max_jmp_ref = jmp_destination;
                        }
                        else
                        {
#if KTHOOK_64
                            jmp.address = jmp_destination;
#else
                            jmp.operand = get_relative_address(jmp_destination,
                                reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr() + trampoline_size), sizeof(jmp));
#endif
                            op_copy_src = &jmp;
                            op_copy_size = sizeof(jmp);

                            // Exit the function if it is not in the branch.
                            finished = (hook_address >= max_jmp_ref);
                        }
                    }
                    // Conditional relative jmp
                    else if (((hs.opcode & 0xF0) == 0x70) ||     // one byte jump
                        ((hs.opcode & 0xFC) == 0xE0) ||     // LOOPNZ/LOOPZ/LOOP/JECXZ
                        ((hs.opcode2 & 0xF0) == 0x80)) {    // two byte jump

                        std::uintptr_t jmp_destination = current_address + hs.len;

                        if ((hs.opcode & 0xF0) == 0x70      // Jcc
                            || (hs.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
                            jmp_destination += hs.imm.imm8;
                        else
                            jmp_destination += hs.imm.imm32;

                        // Simply copy an internal jump.
                        if (hook_address <= jmp_destination
                            && jmp_destination < (hook_address + sizeof(JMP_REL)))
                        {
                            if (max_jmp_ref < jmp_destination)
                                max_jmp_ref = jmp_destination;
                        }
                        else if ((hs.opcode & 0xFC) == 0xE0)
                        {
                            // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
                            return false;
                        }
                        else
                        {
                            std::uint8_t cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
#if KTHOOK_64
                            // Invert the condition in x64 mode to simplify the conditional jump logic.
                            jcc.opcode = 0x71 ^ cond;
                            jcc.address = dest;
#else
                            jcc.opcode1 = 0x80 | cond;
                            jcc.operand = get_relative_address(jmp_destination,
                                reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr() + trampoline_size), sizeof(jcc));
#endif
                            op_copy_src = &jcc;
                            op_copy_size = sizeof(jcc);
                        }
                    }
                    // RET
                    else if ((hs.opcode & 0xFE) == 0xC2)
                    {
                        finished = (current_address >= max_jmp_ref);
                    }

                    trampoline_gen->db(reinterpret_cast<std::uint8_t*>(op_copy_src), op_copy_size);

                    trampoline_size += op_copy_size;
                    current_address += hs.len;

                }

                if (current_address - hook_address < sizeof(JMP_REL))
                    return false;
                return true;
            }

            const std::uint8_t* generate_relay_jump() {
                using namespace Xbyak::util;
                if constexpr (Convention != hook_type_traits::cconv::ccdecl) {
                    jump_gen->pop(eax);
                }
                if constexpr (Convention == hook_type_traits::cconv::cthiscall) {
                    jump_gen->pop(ecx);
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                if constexpr (Convention == hook_type_traits::cconv::ccdecl) {
                    jump_gen->call(relay);
                    jump_gen->add(esp, 4);
                    jump_gen->ret();
                }
                else {
                    jump_gen->push(eax);
                    jump_gen->jmp(relay);
                }
                detail::flush_intruction_cache(reinterpret_cast<void*>(const_cast<std::uint8_t*>(this->jump_gen->getCode())), this->jump_gen->getSize());
                return jump_gen->getCode();
            }

            std::size_t hook_size;
            std::unique_ptr<unsigned char[]> original_code;
            std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;
        };

        enum class kthook_type {
            simple,
            medium,
            complex,
        };

        template <kthook_type hook_type, hook_type_traits::cconv Convention, typename Ret, typename... Args>
        class kthook_impl {};

        template <hook_type_traits::cconv Convention, typename Ret, typename... Args>
        class kthook_impl<kthook_type::simple, Convention, Ret, Args...> : public kthook_internal_impl<Convention, Ret, Args...> {
            using relay_gen_from_this = detail::relay_simple_generator<kthook_impl, Convention, Ret, Args...>;

            friend relay_gen_from_this;
            template <typename FuncSig>
            class hook_signal : public ktsignal::ktsignal_threadsafe<FuncSig> {
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit;
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit_iterate;
                friend relay_gen_from_this;
            };

            template<class T, class Enable = void>
            struct on_after_type {
                using type = hook_signal<void(std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T>
            struct on_after_type<T, typename std::enable_if<!std::is_void_v<T>>::type> {
                using type = hook_signal<void(Ret&, std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T>
            struct on_before_type {
                using type = hook_signal<bool(std::add_lvalue_reference_t<Args>...) >;
            };

            using on_after_type_t = typename on_after_type<Ret>::type;
            using on_before_type_t = typename on_before_type<Ret>::type;
            using kthook_internal_impl<Convention, Ret, Args...>::relay;
            using kthook_internal_impl<Convention, Ret, Args...>::hook_address;
        public:
#ifdef _WIN32
            kthook_impl(void* dest, bool force_install = true) {
#else
            kthook_impl(Ret(*dest)(Args...), bool force_install = true) {
#endif
                relay = reinterpret_cast<void*>(&relay_gen_from_this::relay);
                hook_address = reinterpret_cast<std::uintptr_t>(dest);
                if (force_install)
                    this->install();
            }

            on_before_type_t before;
            on_after_type_t after;
            };

        template <hook_type_traits::cconv Convention, typename Ret, typename... Args>
        class kthook_impl<kthook_type::medium, Convention, Ret, Args...> : public kthook_internal_impl<Convention, Ret, Args...> {
            using relay_gen_from_this = detail::relay_generator<detail::generator_type::simple, kthook_impl, Convention, Ret, Args...>;

            friend relay_gen_from_this;
            template <typename FuncSig>
            class hook_signal : public ktsignal::ktsignal_threadsafe<FuncSig> {
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit;
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit_iterate;
                friend relay_gen_from_this;
            };

            template<class T, class Enable = void>
            struct on_after_type {
                using type = hook_signal<void(std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T>
            struct on_after_type<T, typename std::enable_if<!std::is_void_v<T>>::type> {
                using type = hook_signal<void(Ret&, std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T, class Enable = void>
            struct on_before_type {
                using type = hook_signal<bool(std::add_lvalue_reference_t<Args>...) >;
            };

            template<class T>
            struct on_before_type<T, typename std::enable_if<!std::is_void_v<T>>::type> {
                using type = hook_signal<detail::return_value<T>(std::add_lvalue_reference_t<Args>...) >;
            };

            using on_after_type_t = typename on_after_type<Ret>::type;
            using on_before_type_t = typename on_before_type<Ret>::type;
            using kthook_internal_impl<Convention, Ret, Args...>::relay;
            using kthook_internal_impl<Convention, Ret, Args...>::hook_address;
        public:
#ifdef _WIN32
            kthook_impl(void* dest, bool force_install = true) {
#else
            kthook_impl(Ret(*dest)(Args...), bool force_install = true) {
#endif
                relay = reinterpret_cast<void*>(&relay_gen_from_this::relay);
                hook_address = reinterpret_cast<std::uintptr_t>(dest);
                if (force_install)
                    this->install();
            }

            on_before_type_t before;
            on_after_type_t after;
            };

        template <hook_type_traits::cconv Convention, typename Ret, typename... Args>
        class kthook_impl<kthook_type::complex, Convention, Ret, Args...> : public kthook_internal_impl<Convention, Ret, Args...> {
            using relay_gen_from_this = detail::relay_generator<detail::generator_type::complex, kthook_impl, Convention, Ret, Args...>;

            friend relay_gen_from_this;
            template <typename FuncSig>
            class hook_signal : public ktsignal::ktsignal_threadsafe<FuncSig> {
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit;
                using ktsignal::ktsignal_threadsafe<FuncSig>::emit_iterate;
                friend relay_gen_from_this;
            };

            template<class T, class Enable = void>
            struct on_after_type {
                using type = hook_signal<void(std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T>
            struct on_after_type<T, typename std::enable_if<!std::is_void_v<T>>::type> {
                using type = hook_signal<void(Ret&, std::add_lvalue_reference_t<Args>...)>;
            };

            template<class T, class Enable = void>
            struct on_before_type {
                using type = hook_signal<bool(std::add_lvalue_reference_t<Args>...) >;
            };

            template<class T>
            struct on_before_type<T, typename std::enable_if<!std::is_void_v<T>>::type> {
                using type = hook_signal<detail::return_value<T>(std::add_lvalue_reference_t<Args>...) >;
            };

            template<class T>
            struct on_before_simple_type {
                using type = hook_signal<bool(std::add_lvalue_reference_t<Args>...) >;
            };

            using on_after_type_t = typename on_after_type<Ret>::type;
            using on_before_type_t = typename on_before_type<Ret>::type;
            using on_before_simple_type_t = typename on_before_simple_type<Ret>::type;
            using kthook_internal_impl<Convention, Ret, Args...>::relay;
            using kthook_internal_impl<Convention, Ret, Args...>::hook_address;
        public:
#ifdef _WIN32
            kthook_impl(void* dest, bool force_install = true) {
#else
            kthook_impl(Ret(*dest)(Args...), bool force_install = true) {
#endif
                relay = reinterpret_cast<void*>(&relay_gen_from_this::relay);
                hook_address = reinterpret_cast<std::uintptr_t>(dest);
                if (force_install)
                    this->install();
            }

            on_before_simple_type_t before_simple;
            on_before_type_t before;
            on_after_type_t after;
            };

        template <typename FuncPointerSig>
        struct kthook {};

        template <typename Ret, typename... Args>
        struct kthook<Ret(CCDECL*)(Args...)> {
            using type = kthook_impl<kthook_type::medium, hook_type_traits::cconv::ccdecl, Ret, Args...>;
        };
#ifdef _WIN32
        template <typename Ret, typename... Args>
        struct kthook<Ret(CSTDCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::medium, hook_type_traits::cconv::cstdcall, Ret, Args...>;
        };

        template < typename Ret, typename... Args>
        struct kthook<Ret(CTHISCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::medium, hook_type_traits::cconv::cthiscall, Ret, Args...>;
        };

        template <typename Ret, typename... Args>
        struct kthook<Ret(CFASTCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::medium, hook_type_traits::cconv::cfastcall, Ret, Args...>;
        };
#endif
        template <typename FuncPointerSig>
        struct kthook_simple {};

        template <typename Ret, typename... Args>
        struct kthook_simple<Ret(CCDECL*)(Args...)> {
            using type = kthook_impl<kthook_type::simple, hook_type_traits::cconv::ccdecl, Ret, Args...>;
        };
#ifdef _WIN32
        template <typename Ret, typename... Args>
        struct kthook_simple<Ret(CSTDCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::simple, hook_type_traits::cconv::cstdcall, Ret, Args...>;
        };

        template <typename Ret, typename... Args>
        struct kthook_simple<Ret(CTHISCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::simple, hook_type_traits::cconv::cthiscall, Ret, Args...>;
        };

        template <typename Ret, typename... Args>
        struct kthook_simple<Ret(CFASTCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::simple, hook_type_traits::cconv::cfastcall, Ret, Args...>;
        };
#endif
        template <typename FuncPointerSig>
        struct kthook_complex {};

        template <typename Ret, typename... Args>
        struct kthook_complex<Ret(CCDECL*)(Args...)> {
            using type = kthook_impl<kthook_type::complex, hook_type_traits::cconv::ccdecl, Ret, Args...>;
        };
#ifdef _WIN32
        template <typename Ret, typename... Args>
        struct kthook_complex<Ret(CSTDCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::complex, hook_type_traits::cconv::cstdcall, Ret, Args...>;
        };

        template <typename Ret, typename... Args>
        struct kthook_complex<Ret(CTHISCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::complex, hook_type_traits::cconv::cthiscall, Ret, Args...>;
        };

        template <typename Ret, typename... Args>
        struct kthook_complex<Ret(CFASTCALL*)(Args...)> {
            using type = kthook_impl<kthook_type::complex, hook_type_traits::cconv::cfastcall, Ret, Args...>;
        };
#endif
    }


    template <typename FuncPointerSig>
    using kthook_t = typename detail::kthook<FuncPointerSig>::type;

    template <typename FuncPointerSig>
    using kthook_simple_t = typename detail::kthook_simple<FuncPointerSig>::type;

    template <typename FuncPointerSig>
    using kthook_complex_t = typename detail::kthook_complex<FuncPointerSig>::type;

    using detail::return_value;
}
#endif // KTHOOK_HPP