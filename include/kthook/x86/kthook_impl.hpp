#ifndef KTHOOK_IMPL_HPP_
#define KTHOOK_IMPL_HPP_

namespace kthook {
#pragma pack(push, 1)
struct cpu_ctx {
    cpu_ctx() = default;

    std::uintptr_t edi;
    std::uintptr_t esi;
    std::uintptr_t ebp;
    std::uintptr_t esp;
    std::uintptr_t ebx;
    std::uintptr_t edx;
    std::uintptr_t ecx;
    std::uintptr_t eax;

    struct EFLAGS {
    public:
        std::uintptr_t CF : 1;

    private:
        std::uintptr_t reserved1 : 1;

    public:
        std::uintptr_t PF : 1;

    private:
        std::uintptr_t reserved2 : 1;

    public:
        std::uintptr_t AF : 1;

    private:
        std::uintptr_t reserved3 : 1;

    public:
        std::uintptr_t ZF : 1;
        std::uintptr_t SF : 1;
        std::uintptr_t TF : 1;
        std::uintptr_t IF : 1;
        std::uintptr_t DF : 1;
        std::uintptr_t OF : 1;
        std::uintptr_t IOPL : 2;
        std::uintptr_t NT : 1;

    private:
        std::uintptr_t reserved4 : 1;

    public:
        std::uintptr_t RF : 1;
        std::uintptr_t VM : 1;
        std::uintptr_t AC : 1;
        std::uintptr_t VIF : 1;
        std::uintptr_t VIP : 1;
        std::uintptr_t ID : 1;

    private:
        std::uintptr_t reserved5 : 10;
    } flags;

    std::uint8_t align;
};
#pragma pack(pop)

namespace detail {
struct cpu_ctx_empty {
    std::uintptr_t ecx;
};

inline bool create_trampoline(std::uintptr_t hook_address,
                              const std::unique_ptr<Xbyak::CodeGenerator>& trampoline_gen, bool naked = false) {
    CALL_REL call = {
        0xE8,      // E8 xxxxxxxx: CALL +5+xxxxxxxx
        0x00000000 // Relative destination address
    };
    JMP_REL jmp = {
        0xE9,      // E9 xxxxxxxx: JMP +5+xxxxxxxx
        0x00000000 // Relative destination address
    };
    JCC_REL jcc = {
        0x0F, 0x80, // 0F8* xxxxxxxx: J** +6+xxxxxxxx
        0x00000000  // Relative destination address
    };

    std::size_t trampoline_size = 0;
    std::size_t op_copy_size = 0;
    void* op_copy_src = nullptr;
    std::uintptr_t current_address = hook_address;
    std::uintptr_t max_jmp_ref = 0;
    bool finished = false;

    while (!finished) {
        detail::hde hs;
        std::size_t op_copy_size = hde_disasm(reinterpret_cast<void*>(current_address), &hs);
        if (hs.flags & F_ERROR) return false;
        op_copy_src = reinterpret_cast<void*>(current_address);
        if (current_address - hook_address >= sizeof(call)) {
            if (!naked)
                trampoline_gen->jmp(reinterpret_cast<std::uint8_t*>(current_address));
            break;
        }
        // Relative Call
        else if (hs.opcode == 0xE8) {
            std::uintptr_t call_destination = detail::restore_absolute_address(current_address, hs.imm.imm32, hs.len);
            call.operand = detail::get_relative_address(
                call_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(call));
            op_copy_src = &call;
            op_copy_size = sizeof(call);
        }
        // Relative jmp
        else if ((hs.opcode & 0xFD) == 0xE9) {
            std::uintptr_t jmp_destination = current_address + hs.len;

            if (hs.opcode == 0xEB) // is short jump
                jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
            else
                jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

            if (hook_address <= jmp_destination && jmp_destination < (hook_address + sizeof(JMP_REL))) {
                if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
            } else {
                jmp.operand = detail::get_relative_address(
                    jmp_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jmp));
                op_copy_src = &jmp;
                op_copy_size = sizeof(jmp);

                // Exit the function if it is not in the branch.
                finished = (hook_address >= max_jmp_ref);
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

            // Simply copy an internal jump.
            if (hook_address <= jmp_destination && jmp_destination < (hook_address + sizeof(JMP_REL))) {
                if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
            } else if ((hs.opcode & 0xFC) == 0xE0) {
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
                return false;
            } else {
                std::uint8_t cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
                jcc.opcode1 = 0x80 | cond;
                jcc.operand = detail::get_relative_address(
                    jmp_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jcc));
                op_copy_src = &jcc;
                op_copy_size = sizeof(jcc);
            }
        }
        // RET
        else if ((hs.opcode & 0xFE) == 0xC2) {
            finished = (current_address >= max_jmp_ref);
        }

        trampoline_gen->db(reinterpret_cast<std::uint8_t*>(op_copy_src), op_copy_size);

        trampoline_size += op_copy_size;
        current_address += hs.len;
    }
    if (current_address - hook_address < sizeof(JMP_REL)) return false;
    return true;
}
} // namespace detail

enum kthook_option {
    kNone = 0,
    kCreateContext = 1 << 0,
};

template <typename FunctionPtrT, kthook_option Options = kthook_option::kNone>
class kthook_simple {
    using function = detail::traits::function_traits<FunctionPtrT>;
    using Args = typename function::args;
    using Ret = typename function::return_type;
    using function_ptr = detail::traits::function_connect_ptr_t<function::convention, Ret, Args>;
    using converted_args = detail::traits::add_refs_t<detail::traits::convert_refs_t<Args>>;
    using cb_type = std::function<
        detail::traits::function_connect_t<Ret, detail::traits::tuple_cat_t<const kthook_simple&, converted_args>>>;

    static constexpr auto create_context = Options & kthook_option::kCreateContext;

    struct hook_info {
        std::uintptr_t hook_address;
        std::unique_ptr<unsigned char[]> original_code;

        hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c)
            : hook_address(a),
              original_code(std::move(c)) {
        }

        hook_info(std::uintptr_t a)
            : hook_address(a),
              original_code(nullptr) {
        }
    };

    friend struct detail::relay_generator<kthook_simple, function::convention, Ret, Args>;

public:
    kthook_simple()
        : info(0, nullptr) {
    };

    kthook_simple(std::uintptr_t destination, cb_type callback_, bool force_enable = true)
        : callback(std::move(callback_)),
          info(destination, nullptr) {
        if (force_enable) {
            install();
        }
    }

    kthook_simple(std::uintptr_t destination)
        : info(destination, nullptr) {
    }

    kthook_simple(void* destination)
        : kthook_simple(reinterpret_cast<std::uintptr_t>(destination)) {
    }

    template <typename Ptr>
    kthook_simple(Ptr* destination)
        : kthook_simple(reinterpret_cast<std::uintptr_t>(destination)) {
    }

    kthook_simple(void* destination, cb_type callback, bool force_enable = true)
        : kthook_simple(reinterpret_cast<std::uintptr_t>(destination), callback, force_enable) {
    }

    template <typename Ptr>
    kthook_simple(Ptr* destination, cb_type callback_, bool force_enable = true)
        : kthook_simple(reinterpret_cast<void*>(destination), callback_, force_enable) {
    }

    ~kthook_simple() { remove(); }

    bool install() {
        if (installed) return false;
        if (info.hook_address == 0) return false;
        if (!detail::check_is_executable(reinterpret_cast<void*>(info.hook_address))) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;

        installed = true;
        return true;
    }

    bool remove() {
        if (!installed) return false;
        installed = ! patch_hook(false);
        return !installed;
    }

    bool reset() {
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RWE))
            return false;
        std::memcpy(reinterpret_cast<void*>(info.hook_address), info.original_code.get(), this->hook_size);
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RE))
            return false;
        installed = false;

        return true;
    }

    void set_cb(cb_type callback_) { callback = std::move(callback_); }

    void set_dest(std::uintptr_t address) { info = {address, nullptr}; }

    void set_dest(void* address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    void set_dest(function_ptr address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    std::uintptr_t& get_return_address() const { return last_return_address; }

    const cpu_ctx& get_context() const { return context; }

    const function_ptr get_trampoline() const {
        return reinterpret_cast<function_ptr>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
    }

    cb_type& get_callback() { return callback; }

private:
    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode;
        // this jump gets nopped when hook.remove() is called
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);

        // create trampoline
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        if constexpr (create_context) {
            // save esp
            jump_gen->mov(eax, esp);
            jump_gen->mov(ptr[&last_return_address], eax);
            jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.align));
            jump_gen->pushfd();
            jump_gen->pushad();
            jump_gen->mov(esp, ptr[&last_return_address]);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.esp)], esp);
        }

        // save return address
        jump_gen->mov(eax, ptr[esp]);
        jump_gen->mov(ptr[&last_return_address], eax);
        constexpr bool can_be_pushed = []() {
            if constexpr (function::args_count > 0) {
                using first = std::tuple_element_t<0, Args>;
                return std::is_integral_v<first> || std::is_pointer_v<first>;
            }
            return false;
        }();
        constexpr bool is_thiscall = (function::convention == detail::traits::cconv::cthiscall);
#ifdef _WIN32
        jump_gen->pop(eax);
        if constexpr (!std::is_void_v<Ret>) {
            if constexpr (sizeof(Ret) > 8 || !std::is_trivial_v<Ret>) {
                jump_gen->pop(eax);
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                jump_gen->push(eax);
                jump_gen->mov(eax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
            } else {
                if constexpr (is_thiscall) {
                    if constexpr (can_be_pushed) {
                        jump_gen->push(ecx);
                    }
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
            }
        } else {
            if constexpr (is_thiscall) {
                if constexpr (can_be_pushed) {
                    jump_gen->push(ecx);
                }
            }
            jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
        }
#else
        jump_gen->pop(eax);
        // if Ret is class or union, memory for return value as first argument(hidden)
        // so we need to push our hook pointer after this hidden argument
        if constexpr (!std::is_void_v<Ret>) {
            if constexpr (std::is_class_v<Ret> || std::is_union_v<Ret> || sizeof(Ret) > 8) {
                if constexpr (is_thiscall) {
                    jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                    jump_gen->push(ecx);
                } else {
                    jump_gen->pop(eax);
                    jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                    jump_gen->push(eax);
                    jump_gen->mov(eax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
                }

            } else {
                if constexpr (is_thiscall) {
                    if constexpr (can_be_pushed) {
                        jump_gen->push(ecx);
                    }
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
            }
        } else {
            if constexpr (is_thiscall) {
                if constexpr (can_be_pushed) {
                    jump_gen->push(ecx);
                }
            }
            jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
        }
        static_assert(function::convention != detail::traits::cconv::cfastcall, "linux fastcall not supported");
#endif
        auto relay_ptr =
            reinterpret_cast<void*>(&detail::relay_generator<kthook_simple, function::convention, Ret, Args>::relay);
        if constexpr (function::convention == detail::traits::cconv::ccdecl) {
            // call relay for restoring stack pointer after call
            jump_gen->call(relay_ptr);
            jump_gen->add(esp, 4);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.ecx)], ecx);
            jump_gen->mov(ecx, ptr[&last_return_address]);
            jump_gen->push(ecx);
            jump_gen->mov(ecx, ptr[reinterpret_cast<std::uintptr_t>(&context.ecx)]);
            jump_gen->ret();
        } else {
            jump_gen->push(eax);
            jump_gen->jmp(relay_ptr);
        }
        detail::flush_intruction_cache(jump_gen->getCode(), jump_gen->getSize());
        return jump_gen->getCode();
    }

    bool patch_hook(bool enable) {
        if (enable) {
#pragma pack(push, 1)
            struct {
                std::uint8_t opcode;
                std::uint32_t operand;
            } patch;
#pragma pack(pop)
            if (!this->relay_jump) {
                this->relay_jump = generate_relay_jump();
                this->hook_size = detail::detect_hook_size(info.hook_address);
                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = relative;
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    cb_type callback{};
    hook_info info;
    mutable std::uintptr_t last_return_address{0};
    std::size_t hook_size{0};
    std::unique_ptr<Xbyak::CodeGenerator> jump_gen{
        std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, nullptr, &detail::default_jmp_allocator)};
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen{std::make_unique<Xbyak::CodeGenerator>()};
    std::uint64_t original{0};
    const std::uint8_t* relay_jump{nullptr};
    std::conditional_t<Options & kthook_option::kCreateContext, cpu_ctx, detail::cpu_ctx_empty> context{};
    bool using_ptr_to_return_address = true;
    bool installed = false;
};

template <typename FunctionPtrT, kthook_option Options = kthook_option::kNone>
class kthook_signal {
    using function = detail::traits::function_traits<FunctionPtrT>;
    using Args = detail::traits::convert_refs_t<typename function::args>;
    using Ret = detail::traits::convert_ref_t<typename function::return_type>;
    using function_ptr = typename detail::traits::function_connect_ptr_t<function::convention, Ret, Args>;
    using converted_args = detail::traits::convert_refs_t<Args>;
    using before_t = typename detail::traits::on_before_t<kthook_signal, Ret, converted_args>;
    using after_t = typename detail::traits::on_after_t<kthook_signal, Ret, converted_args>;

    static constexpr auto create_context = Options & kthook_option::kCreateContext;

    struct hook_info {
        std::uintptr_t hook_address;
        std::unique_ptr<unsigned char[]> original_code;

        hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c)
            : hook_address(a),
              original_code(std::move(c)) {
        }

        hook_info(std::uintptr_t a)
            : hook_address(a),
              original_code(nullptr) {
        }
    };

    friend struct detail::signal_relay_generator<kthook_signal, function::convention, Ret, Args>;

public:
    kthook_signal()
        : info(0, nullptr) {
    }

    kthook_signal(std::uintptr_t destination, bool force_enable = true)
        : info(destination, nullptr) {
        if (force_enable) {
            install();
        }
    }

    kthook_signal(void* destination, bool force_enable = true)
        : kthook_signal(reinterpret_cast<std::uintptr_t>(destination), force_enable) {
    }

    template <typename Ptr>
    kthook_signal(Ptr* destination, bool force_enable = true)
        : kthook_signal(reinterpret_cast<void*>(destination), force_enable) {
    }

    ~kthook_signal() { remove(); }

    bool install() {
        if (installed) return false;
        if (!detail::check_is_executable(reinterpret_cast<void*>(info.hook_address))) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;
        installed = true;
        return true;
    }

    bool remove() {
        if (!installed) return false;
        installed = !patch_hook(false);
        return !installed;
    }

    bool reset() {
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RWE))
            return false;
        std::memcpy(reinterpret_cast<void*>(info.hook_address), info.original_code.get(), this->hook_size);
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RE))
            return false;
        installed = false;
        return true;
    }

    void set_dest(std::uintptr_t address) { info = {address, nullptr}; }

    void set_dest(void* address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    void set_dest(function_ptr address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    std::uintptr_t& get_return_address() const { return last_return_address; }

    const cpu_ctx& get_context() const { return context; }

    const function_ptr get_trampoline() {
        return reinterpret_cast<function_ptr>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
    }

    before_t before;
    after_t after;

private:
    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode;
        // this jump gets nopped when hook.remove() is called
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);

        // create trampoline
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        if constexpr (create_context) {
            // save esp
            jump_gen->mov(eax, esp);
            jump_gen->mov(ptr[&last_return_address], eax);
            jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.align));
            jump_gen->pushfd();
            jump_gen->pushad();
            jump_gen->mov(esp, ptr[&last_return_address]);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.esp)], esp);
        }

        jump_gen->mov(eax, ptr[esp]);
        jump_gen->mov(ptr[&last_return_address], eax);

        // pop return address out
        constexpr bool can_be_pushed = []() {
            if constexpr (function::args_count > 0) {
                using first = std::tuple_element_t<0, Args>;
                return std::is_integral_v<first> || std::is_pointer_v<first>;
            }
            return false;
        }();
        constexpr bool is_thiscall = (function::convention == detail::traits::cconv::cthiscall);
#ifdef _WIN32
        jump_gen->pop(eax);
        if constexpr (!std::is_void_v<Ret>) {
            if constexpr (sizeof(Ret) > 8 || !std::is_trivial_v<Ret>) {
                jump_gen->pop(eax);
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                jump_gen->push(eax);
                jump_gen->mov(eax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
            } else {
                if constexpr (is_thiscall) {
                    if constexpr (can_be_pushed) {
                        jump_gen->push(ecx);
                    }
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
            }
        } else {
            if constexpr (is_thiscall) {
                if constexpr (can_be_pushed) {
                    jump_gen->push(ecx);
                }
            }
            jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
        }
#else
        jump_gen->pop(eax);
        // if Ret is class or union, memory for return value as first argument(hidden)
        // so we need to push our hook pointer after this hidden argument
        if constexpr (!std::is_void_v<Ret>) {
            if constexpr (std::is_class_v<Ret> || std::is_union_v<Ret> || sizeof(Ret) > 8) {
                if constexpr (is_thiscall) {
                    jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                    jump_gen->push(ecx);
                } else {
                    jump_gen->pop(eax);
                    jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                    jump_gen->push(eax);
                    jump_gen->mov(eax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
                }

            } else {
                if constexpr (is_thiscall) {
                    if constexpr (can_be_pushed) {
                        jump_gen->push(ecx);
                    }
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
            }
        } else {
            if constexpr (is_thiscall) {
                if constexpr (can_be_pushed) {
                    jump_gen->push(ecx);
                }
            }
            jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
        }
        static_assert(function::convention != detail::traits::cconv::cfastcall, "linux fastcall not supported");
#endif
        auto relay_ptr = reinterpret_cast<void*>(
            &detail::signal_relay_generator<kthook_signal, function::convention, Ret, Args>::relay);
        if constexpr (function::convention == detail::traits::cconv::ccdecl) {
            // call relay for restoring stack pointer after call
            jump_gen->call(relay_ptr);
            jump_gen->add(esp, 4);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.ecx)], ecx);
            jump_gen->mov(ecx, ptr[&last_return_address]);
            jump_gen->push(ecx);
            jump_gen->mov(ecx, ptr[reinterpret_cast<std::uintptr_t>(&context.ecx)]);
            jump_gen->ret();
        } else {
            jump_gen->push(eax);
            jump_gen->jmp(relay_ptr);
        }
        detail::flush_intruction_cache(jump_gen->getCode(), jump_gen->getSize());
        return jump_gen->getCode();
    }

    bool patch_hook(bool enable) {
        if (enable) {
#pragma pack(push, 1)
            struct {
                std::uint8_t opcode;
                std::uint32_t operand;
            } patch;
#pragma pack(pop)
            if (!this->relay_jump) {
                this->relay_jump = generate_relay_jump();
                this->hook_size = detail::detect_hook_size(info.hook_address);
                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = relative;
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    hook_info info;
    mutable std::uintptr_t last_return_address{0};
    std::size_t hook_size = 0;
    std::unique_ptr<Xbyak::CodeGenerator> jump_gen{
        std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, nullptr, &detail::default_jmp_allocator)};
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen{std::make_unique<Xbyak::CodeGenerator>()};
    std::uint64_t original = 0;
    const std::uint8_t* relay_jump = nullptr;
    std::conditional_t<create_context, cpu_ctx, detail::cpu_ctx_empty> context{};

    bool installed = false;
};

class kthook_naked {
    using cb_type = std::function<void(const kthook_naked&)>;

    struct hook_info {
        std::uintptr_t hook_address;
        std::unique_ptr<unsigned char[]> original_code;

        hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c)
            : hook_address(a),
              original_code(std::move(c)) {
        }

        hook_info(std::uintptr_t a)
            : hook_address(a),
              original_code(nullptr) {
        }
    };

public:
    kthook_naked()
        : info(0, nullptr) {
    };

    kthook_naked(std::uintptr_t destination, cb_type callback_, bool force_enable = true)
        : info(destination, nullptr),
          callback(std::move(callback_)) {
        if (force_enable) {
            install();
        }
    }

    kthook_naked(std::uintptr_t destination)
        : info(destination, nullptr) {
    }

    kthook_naked(void* destination)
        : kthook_naked(reinterpret_cast<std::uintptr_t>(destination)) {
    }

    kthook_naked(void* destination, cb_type callback, bool force_enable = true)
        : kthook_naked(reinterpret_cast<std::uintptr_t>(destination), callback, force_enable) {
    }

    ~kthook_naked() { remove(); }

    bool install() {
        if (installed) return false;
        if (info.hook_address == 0) return false;
        if (!detail::check_is_executable(reinterpret_cast<void*>(info.hook_address))) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;
        installed = true;
        return true;
    }

    bool remove() {
        if (!installed) return false;
        installed = !patch_hook(false);
        return !installed;
    }

    bool reset() {
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RWE))
            return false;
        std::memcpy(reinterpret_cast<void*>(info.hook_address), info.original_code.get(), this->hook_size);
        if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                             detail::MemoryProt::PROTECT_RE))
            return false;
        installed = false;
        return true;
    }

    void set_cb(cb_type callback_) { callback = std::move(callback_); }

    void set_dest(std::uintptr_t address) { info = {address, nullptr}; }

    void set_dest(void* address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    std::uintptr_t& get_return_address() const { return last_return_address; }

    cpu_ctx& get_context() const { return context; }

    cb_type& get_callback() { return callback; }

private:
    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode, ret_addr;
        // this jump gets nopped when hook.remove() is called
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);

        // create trampoline
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        // save esp
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.eax)], eax);
        jump_gen->mov(eax, esp);
        jump_gen->mov(ptr[&last_return_address], eax);
        jump_gen->mov(eax, ptr[reinterpret_cast<std::uintptr_t>(&context.eax)]);

        jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.align));
        jump_gen->pushfd();
        jump_gen->pushad();
        jump_gen->mov(esp, ptr[&last_return_address]);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.esp)], esp);
        jump_gen->mov(eax, ret_addr);

        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], info.hook_address + hook_size);

        jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
        jump_gen->push(eax);

        jump_gen->jmp(reinterpret_cast<const void*>(&detail::naked_relay<kthook_naked>));
        jump_gen->L(ret_addr);
        jump_gen->add(esp, 0x04);
        jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.edi));
        jump_gen->popad();
        jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.flags));
        jump_gen->popfd();
        jump_gen->mov(esp, ptr[reinterpret_cast<std::uintptr_t>(&context.esp)]);

        detail::create_trampoline(info.hook_address, jump_gen, true);

        jump_gen->jmp(ptr[&last_return_address]);

        detail::flush_intruction_cache(jump_gen->getCode(), jump_gen->getSize());
        return jump_gen->getCode();
    }

    bool patch_hook(bool enable) {
        if (enable) {
#pragma pack(push, 1)
            struct {
                std::uint8_t opcode;
                std::uint32_t operand;
            } patch;
#pragma pack(pop)
            if (!this->relay_jump) {
                this->relay_jump = generate_relay_jump();
                this->hook_size = detail::detect_hook_size(info.hook_address);
                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = relative;
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    hook_info info;
    cb_type callback{};
    std::size_t hook_size{0};
    std::uint64_t original{0};

    mutable std::uintptr_t last_return_address{0};
    mutable cpu_ctx context{};

    std::unique_ptr<Xbyak::CodeGenerator> jump_gen{
        std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, nullptr, &detail::default_jmp_allocator)};
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen{std::make_unique<Xbyak::CodeGenerator>()};

    const std::uint8_t* relay_jump{nullptr};

    bool installed = false;
};
} // namespace kthook

#endif  // KTHOOK_IMPL_HPP_
