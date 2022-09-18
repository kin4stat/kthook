#ifndef KTHOOK_IMPL_HPP_
#define KTHOOK_IMPL_HPP_

namespace kthook {
#pragma pack(push, 1)
struct cpu_ctx {
    struct eflags {
    public:
        std::uint32_t CF : 1;

    private:
        std::uint32_t reserved1 : 1;

    public:
        std::uint32_t PF : 1;

    private:
        std::uint32_t reserved2 : 1;

    public:
        std::uint32_t AF : 1;

    private:
        std::uint32_t reserved3 : 1;

    public:
        std::uint32_t ZF : 1;
        std::uint32_t SF : 1;
        std::uint32_t TF : 1;
        std::uint32_t IF : 1;
        std::uint32_t DF : 1;
        std::uint32_t OF : 1;
        std::uint32_t IOPL : 2;
        std::uint32_t NT : 1;

    private:
        std::uint32_t reserved4 : 1;

    public:
        std::uint32_t RF : 1;
        std::uint32_t VM : 1;
        std::uint32_t AC : 1;
        std::uint32_t VIF : 1;
        std::uint32_t VIP : 1;
        std::uint32_t ID : 1;

    private:
        std::uint32_t reserved5 : 10;
        std::uint32_t reserved6 : 32;
    };

    std::uintptr_t rax;
    std::uintptr_t rbx;
    std::uintptr_t rcx;
    std::uintptr_t rdx;
    std::uintptr_t rsp;
    std::uintptr_t rbp;
    std::uintptr_t rsi;
    std::uintptr_t rdi;
    std::uintptr_t r8;
    std::uintptr_t r9;
    std::uintptr_t r10;
    std::uintptr_t r11;
    std::uintptr_t r12;
    std::uintptr_t r13;
    std::uintptr_t r14;
    std::uintptr_t r15;
    eflags* flags;
};
#pragma pack(pop)

namespace detail {
struct cpu_ctx_empty {
    std::uintptr_t rax;
    std::uintptr_t rcx;
};

inline bool create_trampoline(std::uintptr_t hook_address,
                              const std::unique_ptr<Xbyak::CodeGenerator>& trampoline_gen, bool naked = false) {
    CALL_ABS call = {
        0xFF,
        0x15,
        0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB,
        0x08,                 // EB 08:         JMP +10
        0x0000000000000000ULL // Absolute destination address
    };
    JMP_ABS jmp = {
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    JCC_ABS jcc = {
        0x70,
        0x0E, // 7* 0E:         J** +16
        0xFF,
        0x25,
        0x00000000,           // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL // Absolute destination address
    };

    std::size_t trampoline_size = 0;
    std::size_t op_copy_size = 0;
    void* op_copy_src = nullptr;
    std::uintptr_t current_address = hook_address;
    std::uintptr_t max_jmp_ref = 0;
    std::uint8_t inst_buf[16];
    bool finished = false;

    while (!finished) {
        detail::hde hs;
        std::size_t op_copy_size = hde_disasm(reinterpret_cast<void*>(current_address), &hs);
        if (hs.flags & F_ERROR) return false;
        op_copy_src = reinterpret_cast<void*>(current_address);
        if (current_address - hook_address >= sizeof(JMP_REL)) {
            using namespace Xbyak::util;
            if (!naked) {
                trampoline_gen->jmp(ptr[rip]);
                trampoline_gen->db(current_address, 8);
            }
            break;
        } else if ((hs.modrm & 0xC7) == 0x05) {
            // Instructions using RIP relative addressing. (ModR/M = 00???101B)

            // Modify the RIP relative address.
            std::uint32_t* pRelAddr;

            std::memcpy(inst_buf, reinterpret_cast<void*>(current_address), op_copy_size);

            op_copy_src = inst_buf;

            // Relative address is stored at (instruction length - immediate value length - 4).
            pRelAddr = reinterpret_cast<std::uint32_t*>(inst_buf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
            auto value_pointer = current_address + static_cast<std::int32_t>(hs.disp.disp32);
            *pRelAddr = static_cast<uint32_t>(value_pointer -
                                              reinterpret_cast<const std::uintptr_t>(trampoline_gen->getCurr()));

            // Complete the function if JMP (FF /4).
            if (hs.opcode == 0xFF && hs.modrm_reg == 4) finished = true;
        }
        // Relative Call
        else if (hs.opcode == 0xE8) {
            std::uintptr_t call_destination = detail::restore_absolute_address(current_address, hs.imm.imm32, hs.len);
            jmp.address = call_destination;
            op_copy_src = &jmp;
            op_copy_size = sizeof(jmp);
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
                jmp.address = jmp_destination;
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
                // Invert the condition in x64 mode to simplify the conditional jump logic.
                jcc.opcode = 0x71 ^ cond;
                jcc.address = jmp_destination;
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
    kFreezeThreads = 1 << 1,
};

template <typename FunctionPtr, kthook_option Options = kthook_option::kNone>
class kthook_simple {
    static_assert(std::is_member_function_pointer_v<FunctionPtr> ||
                  std::is_function_v<std::remove_pointer_t<FunctionPtr>> || std::is_function_v<FunctionPtr>,
        "T is not member function pointer/function pointer/function");

    using function = detail::traits::function_traits<FunctionPtr>;
    using Args = typename function::args;
    using Ret = typename function::return_type;
    using function_ptr = typename detail::traits::function_connect_ptr_t<Ret, Args>;
    using converted_args = typename detail::traits::add_refs_t<detail::traits::convert_refs_t<Args>>;
    using cb_type = std::function<
        detail::traits::function_connect_t<Ret, detail::traits::tuple_cat_t<const kthook_simple&, converted_args>>>;

    static constexpr auto create_context = Options & kthook_option::kCreateContext;
    static constexpr auto freeze_threads = Options & kthook_option::kFreezeThreads;

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
    kthook_simple()
        : info(0, nullptr) {
    }

    kthook_simple(std::uintptr_t destination, cb_type callback_, bool force_enable = true)
        : info(destination, nullptr),
          callback(std::move(callback_)) {
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

    kthook_simple(function_ptr destination)
        : kthook_simple(reinterpret_cast<std::uintptr_t>(destination)) {
    }

    kthook_simple(void* destination, cb_type callback, bool force_enable = true)
        : kthook_simple(reinterpret_cast<std::uintptr_t>(destination), callback, force_enable) {
    }

    template <typename Ptr>
    kthook_simple(function_ptr destination, cb_type callback_, bool force_enable = true)
        : kthook_simple(reinterpret_cast<void*>(destination), callback_, force_enable) {
    }

    ~kthook_simple() { remove(); }

    bool install() {
        if (installed) return false;
        if (info.hook_address == 0) return false;
        if (!detail::check_is_executable(reinterpret_cast<void*>(info.hook_address))) return false;
        if (!create_generators()) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;
        if (!detail::flush_intruction_cache(reinterpret_cast<void*>(info.hook_address), hook_size)) return false;
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

    template <typename C, typename S = decltype(&C::template operator()<const kthook_simple&>)>
    void set_cb_wrapped(C cb) {
        callback = [cb = std::forward<C>(cb)](auto&&... args) {
            std::apply(cb, detail::bind_values<detail::traits::args<S>>(
                           std::forward_as_tuple(std::forward<decltype(args)>(args)...)));
        };
    }

    void set_dest(std::uintptr_t address) { info = {address, nullptr}; }

    void set_dest(void* address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    void set_dest(function_ptr address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    std::uintptr_t get_return_address() const {
        return (using_ptr_to_return_address)
                   ? *last_return_address
                   : reinterpret_cast<std::uintptr_t>(last_return_address);
    }

    std::uintptr_t* get_return_address_ptr() const {
        return (using_ptr_to_return_address)
                   ? last_return_address
                   : reinterpret_cast<std::uintptr_t*>(&last_return_address);
    }

    const cpu_ctx& get_context() const { return context; }

    function_ptr get_trampoline() const {
        return reinterpret_cast<function_ptr>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
    }

    template <typename... Ts>
    Ret call_trampoline(Ts&&... args) const {
        return std::apply(get_trampoline(), detail::unpack<Args>(std::forward<Ts>(args)...));
    }

    cb_type& get_callback() { return callback; }

private:
    bool create_generators() {
        void* alloc = detail::try_alloc_near(info.hook_address);
        if (alloc == nullptr) return false;
        void* jump_alloc = alloc;
        auto trampoline_alloc = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(jump_alloc) + 0x800);
        jump_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, jump_alloc,
                                                          &detail::default_jmp_allocator);
        trampoline_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, trampoline_alloc,
                                                                &detail::default_trampoline_allocator);
        return true;
    }

    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode, ret_addr;
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        if constexpr (create_context) {
            jump_gen->pushfq();

            jump_gen->push(rax);
            jump_gen->push(rbx);
            jump_gen->mov(rax, ptr[rsp + sizeof(std::uintptr_t)]);
            jump_gen->xchg(rbx, rax);
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(&context.flags));
            jump_gen->mov(ptr[rax], rbx);
            jump_gen->pop(rbx);
            jump_gen->pop(rax);
            jump_gen->add(rsp, sizeof(cpu_ctx::eflags));

            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rax)], rax);
            jump_gen->mov(rax, rsp);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)], rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);

            jump_gen->mov(rsp, reinterpret_cast<std::uintptr_t>(&context.flags));
            jump_gen->push(r15);
            jump_gen->push(r14);
            jump_gen->push(r13);
            jump_gen->push(r12);
            jump_gen->push(r11);
            jump_gen->push(r10);
            jump_gen->push(r9);
            jump_gen->push(r8);
            jump_gen->push(rdi);
            jump_gen->push(rsi);
            jump_gen->push(rbp);
            jump_gen->sub(rsp, sizeof(std::uintptr_t));
            jump_gen->push(rdx);
            jump_gen->push(rcx);
            jump_gen->push(rbx);

            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)]);
            jump_gen->mov(rsp, rax);
        } else {
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rax)], rax);
        }
        jump_gen->mov(rax, rsp);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);

#if defined(KTHOOK_64_WIN)
        constexpr std::array registers{rcx, rdx, r8, r9};
#elif defined(KTHOOK_64_GCC)
        constexpr std::array registers{rdi, rsi, rdx, rcx, r8, r9};
#endif
        constexpr detail::traits::relay_args_info args_info =
            detail::traits::get_head_and_tail_size<registers.size(), Ret, Args>::value;
        using head = detail::traits::get_first_n_types_t<args_info.head_size, Args>;
        using tail = detail::traits::get_last_n_types_t<args_info.tail_size, Args, function::args_count>;

        if constexpr (args_info.register_idx_if_full == -1) {
            auto relay_ptr =
                reinterpret_cast<void*>(&detail::common_relay_generator<kthook_simple, Ret, head, tail, Args>::relay);
            using_ptr_to_return_address = false;

            // save context
            jump_gen->mov(rax, rcx);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rcx)], rax);

            // pop out return address
            jump_gen->pop(rcx);

#ifdef KTHOOK_64_WIN
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(this));
            // set rsp to next stack argument pointer
            jump_gen->add(rsp, static_cast<std::uint32_t>(sizeof(void*) * registers.size()));
            jump_gen->push(0);
            jump_gen->push(rax);
#else
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(this));
            // push our hook to the stack
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(rax);
#endif

#ifdef KTHOOK_64_WIN
            // return the rsp to its initial state
            jump_gen->sub(rsp, static_cast<std::uint32_t>(sizeof(void*) * registers.size()));
#else

#endif
            // save return address
            jump_gen->mov(rax, rcx);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
            // push our return address
            jump_gen->mov(rax, ret_addr);
            jump_gen->push(rax);

            // restore context
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rcx)]);
            jump_gen->mov(rcx, rax);

            jump_gen->jmp(ptr[rip]);
            jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            jump_gen->L(ret_addr);
#ifdef KTHOOK_64_WIN
            jump_gen->add(rsp, sizeof(void*) * 2);
#else
            jump_gen->add(rsp, 32);
#endif
            // push original return address and return
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
            jump_gen->push(rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
            jump_gen->ret();

        } else {
            using_ptr_to_return_address = true;
            jump_gen->mov(rax, rsp);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
            jump_gen->mov(registers[args_info.register_idx_if_full], reinterpret_cast<std::uintptr_t>(this));
            jump_gen->jmp(ptr[rip]);
            if constexpr (args_info.register_idx_if_full == 2) {
                auto relay_ptr =
                    reinterpret_cast<void*>(&detail::common_relay_generator_three_args<
                        kthook_simple, Ret, head, tail, Args>::relay);
                jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            } else {
                auto relay_ptr =
                    reinterpret_cast<void*>(&detail::common_relay_generator<
                        kthook_simple, Ret, head, tail, Args>::relay);
                jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            }
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
                this->hook_size = detail::detect_hook_size(info.hook_address);
                this->relay_jump = generate_relay_jump();
                detail::frozen_threads threads;

                if constexpr (freeze_threads)
                    if (!detail::freeze_threads(threads))
                        return false;
                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                std::uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = static_cast<std::uint32_t>(relative);
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;
                if constexpr (freeze_threads)
                    if (!detail::unfreeze_threads(threads))
                        return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        if (jump_gen.get()) detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    hook_info info;
    cb_type callback;
    mutable std::uintptr_t* last_return_address = nullptr;
    std::size_t hook_size = 0;
    std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;
    std::uint64_t original = 0;
    const std::uint8_t* relay_jump = nullptr;
    std::conditional_t<create_context, cpu_ctx, detail::cpu_ctx_empty> context;
    bool using_ptr_to_return_address = true;
    bool installed = false;
};

template <typename FunctionPtrT, kthook_option Options = kthook_option::kNone>
class kthook_signal {
    using function = detail::traits::function_traits<FunctionPtrT>;
    using Args = detail::traits::convert_refs_t<typename function::args>;
    using Ret = detail::traits::convert_ref_t<typename function::return_type>;
    using function_ptr = typename detail::traits::function_connect_ptr_t<Ret, Args>;
    using before_t = typename detail::traits::on_before_t<kthook_signal, Ret, Args>;
    using after_t = typename detail::traits::on_after_t<kthook_signal, Ret, Args>;

    static constexpr auto create_context = Options & kthook_option::kCreateContext;
    static constexpr auto freeze_threads = Options & kthook_option::kFreezeThreads;

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

    kthook_signal(function_ptr destination, bool force_enable = true)
        : kthook_signal(reinterpret_cast<void*>(destination), force_enable) {
    }

    ~kthook_signal() { remove(); }

    bool install() {
        if (installed) return false;
        if (info.hook_address == 0) return false;
        if (!detail::check_is_executable(reinterpret_cast<void*>(info.hook_address))) return false;
        if (!create_generators()) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;
        if (!detail::flush_intruction_cache(reinterpret_cast<void*>(info.hook_address), hook_size)) return false;
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

    std::uintptr_t get_return_address() const {
        return (using_ptr_to_return_address)
                   ? *last_return_address
                   : reinterpret_cast<std::uintptr_t>(last_return_address);
    }

    std::uintptr_t* get_return_address_ptr() const {
        return (using_ptr_to_return_address)
                   ? last_return_address
                   : reinterpret_cast<std::uintptr_t*>(&last_return_address);
    }

    const cpu_ctx& get_context() const { return context; }

    function_ptr get_trampoline() const {
        return reinterpret_cast<function_ptr>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
    }

    before_t before;
    after_t after;

private:
    bool create_generators() {
        void* alloc = detail::try_alloc_near(info.hook_address);
        if (alloc == nullptr) return false;
        void* jump_alloc = alloc;
        auto trampoline_alloc = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(jump_alloc) + 0x800);
        jump_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, jump_alloc,
                                                          &detail::default_jmp_allocator);
        trampoline_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, trampoline_alloc,
                                                                &detail::default_trampoline_allocator);
        return true;
    }

    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode, ret_addr;
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        if constexpr (create_context) {
            jump_gen->pushfq();

            jump_gen->push(rax);
            jump_gen->push(rbx);
            jump_gen->mov(rax, ptr[rsp + sizeof(std::uintptr_t)]);
            jump_gen->xchg(rbx, rax);
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(&context.flags));
            jump_gen->mov(ptr[rax], rbx);
            jump_gen->pop(rbx);
            jump_gen->pop(rax);
            jump_gen->add(rsp, sizeof(cpu_ctx::eflags));

            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rax)], rax);
            jump_gen->mov(rax, rsp);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)], rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);

            jump_gen->mov(rsp, reinterpret_cast<std::uintptr_t>(&context.flags));
            jump_gen->push(r15);
            jump_gen->push(r14);
            jump_gen->push(r13);
            jump_gen->push(r12);
            jump_gen->push(r11);
            jump_gen->push(r10);
            jump_gen->push(r9);
            jump_gen->push(r8);
            jump_gen->push(rdi);
            jump_gen->push(rsi);
            jump_gen->push(rbp);
            jump_gen->sub(rsp, sizeof(std::uintptr_t));
            jump_gen->push(rdx);
            jump_gen->push(rcx);
            jump_gen->push(rbx);

            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)]);
            jump_gen->mov(rsp, rax);
        } else {
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rax)], rax);
        }
        jump_gen->mov(rax, rsp);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);

#if defined(KTHOOK_64_WIN)
        constexpr std::array registers{rcx, rdx, r8, r9};
#elif defined(KTHOOK_64_GCC)
        constexpr std::array registers{rdi, rsi, rdx, rcx, r8, r9};
#endif
        constexpr detail::traits::relay_args_info args_info =
            detail::traits::get_head_and_tail_size<registers.size(), Ret, Args>::value;
        using head = detail::traits::get_first_n_types_t<args_info.head_size, Args>;
        using tail = detail::traits::get_last_n_types_t<args_info.tail_size, Args, function::args_count>;

        if constexpr (args_info.register_idx_if_full == -1) {

            auto relay_ptr =
                reinterpret_cast<void*>(&detail::signal_relay_generator<kthook_signal, Ret, head, tail, Args>::relay);
            using_ptr_to_return_address = false;

            // save context
            jump_gen->mov(rax, rcx);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rcx)], rax);

            // pop out return address
            jump_gen->pop(rcx);

#ifdef KTHOOK_64_WIN
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(this));
            // set rsp to next stack argument pointer
            jump_gen->add(rsp, static_cast<std::uint32_t>(sizeof(void*) * registers.size()));
            jump_gen->push(0);
            jump_gen->push(rax);
#else
            jump_gen->mov(rax, reinterpret_cast<std::uintptr_t>(this));
            // push our hook to the stack
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(std::uintptr_t(0));
            jump_gen->push(rax);
#endif

#ifdef KTHOOK_64_WIN
            // return the rsp to its initial state
            jump_gen->sub(rsp, static_cast<std::uint32_t>(sizeof(void*) * registers.size()));
#else

#endif
            // save return address
            jump_gen->mov(rax, rcx);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
            // push our return address
            jump_gen->mov(rax, ret_addr);
            jump_gen->push(rax);

            // restore context
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rcx)]);
            jump_gen->mov(rcx, rax);

            jump_gen->jmp(ptr[rip]);
            jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            jump_gen->L(ret_addr);
#ifdef KTHOOK_64_WIN
            jump_gen->add(rsp, sizeof(void*) * 2);
#else
            jump_gen->add(rsp, 32);
#endif
            // push original return address and return
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
            jump_gen->push(rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
            jump_gen->ret();

        } else {
            using_ptr_to_return_address = true;
            jump_gen->mov(rax, rsp);
            jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
            jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
            jump_gen->mov(registers[args_info.register_idx_if_full], reinterpret_cast<std::uintptr_t>(this));
            jump_gen->jmp(ptr[rip]);
            if constexpr (args_info.register_idx_if_full == 2) {
                auto relay_ptr =
                    reinterpret_cast<void*>(&detail::signal_relay_generator_three_args<
                        kthook_signal, Ret, head, tail, Args>::relay);
                jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            } else {
                auto relay_ptr =
                    reinterpret_cast<void*>(&detail::signal_relay_generator<
                        kthook_signal, Ret, head, tail, Args>::relay);
                jump_gen->db(reinterpret_cast<std::uintptr_t>(relay_ptr), 8);
            }
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
                this->hook_size = detail::detect_hook_size(info.hook_address);
                this->relay_jump = generate_relay_jump();

                detail::frozen_threads threads;

                if constexpr (freeze_threads)
                    if (!detail::freeze_threads(threads))
                        return false;

                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                std::uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = static_cast<std::uint32_t>(relative);
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;
                if constexpr (freeze_threads)
                    if (!detail::unfreeze_threads(threads))
                        return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        if (jump_gen.get()) detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    hook_info info;
    mutable std::uintptr_t* last_return_address = nullptr;
    std::size_t hook_size = 0;
    std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;
    std::uint64_t original = 0;
    const std::uint8_t* relay_jump = nullptr;
    std::conditional_t<create_context, cpu_ctx, detail::cpu_ctx_empty> context;
    bool using_ptr_to_return_address = true;
    bool installed = false;
};

class kthook_naked {
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

    using cb_type = std::function<void(const kthook_naked&)>;
    friend std::uintptr_t detail::naked_relay<kthook_naked>(kthook_naked*);
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
        if (!create_generators()) return false;
        if (!detail::create_trampoline(info.hook_address, trampoline_gen)) return false;
        if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
        if (!patch_hook(true)) return false;
        if (!detail::flush_intruction_cache(reinterpret_cast<void*>(info.hook_address), hook_size)) return false;
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
        return true;
    }

    [[nodiscard]] cb_type& get_callback() { return callback; }

    void set_cb(cb_type callback_) { callback = std::move(callback_); }

    void set_dest(std::uintptr_t address) { info = {address, nullptr}; }

    void set_dest(void* address) { set_dest(reinterpret_cast<std::uintptr_t>(address)); }

    cpu_ctx& get_context() const { return context; }
    std::uintptr_t& get_return_address() const { return last_return_address; }

private:
    const std::uint8_t* generate_relay_jump() {
        using namespace Xbyak::util;

        auto hook_address = info.hook_address;

        Xbyak::Label UserCode, ret_addr, jump_in_trampoline, skip_bytes, jump_out;
        jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
        jump_gen->nop(3);
        detail::create_trampoline(hook_address, jump_gen);
        jump_gen->L(UserCode);

        jump_gen->push(std::uintptr_t{});
        jump_gen->pushfq();

        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rax)], rax);
        jump_gen->mov(rax, rsp);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);

        // [rsp - 0x00] == 0
        // [rsp - 0x08] == eflags
        // last_return_address == rsp - 0x10

        jump_gen->mov(rsp, reinterpret_cast<std::uintptr_t>(&context.flags));
        jump_gen->push(r15);
        jump_gen->push(r14);
        jump_gen->push(r13);
        jump_gen->push(r12);
        jump_gen->push(r11);
        jump_gen->push(r10);
        jump_gen->push(r9);
        jump_gen->push(r8);
        jump_gen->push(rdi);
        jump_gen->push(rsi);
        jump_gen->push(rbp);
        jump_gen->sub(rsp, sizeof(std::uintptr_t));
        jump_gen->push(rdx);
        jump_gen->push(rcx);
        jump_gen->push(rbx);

        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
        jump_gen->mov(rsp, rax);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.flags)], rax);
        jump_gen->add(rax, sizeof(cpu_ctx::eflags) + sizeof(std::uintptr_t));
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)], rax);
        jump_gen->mov(rax, info.hook_address);
        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);
        jump_gen->mov(rax, ret_addr);

#if defined(KTHOOK_64_WIN)
        jump_gen->mov(rcx, reinterpret_cast<std::uintptr_t>(this));
        jump_gen->sub(rsp, sizeof(std::uintptr_t) * 8);
#elif defined(KTHOOK_64_GCC)
        jump_gen->mov(rdi, reinterpret_cast<std::uintptr_t>(this));
#endif

        jump_gen->push(rax);
        jump_gen->jmp(ptr[rip]);
        jump_gen->db(reinterpret_cast<std::uintptr_t>(&detail::naked_relay<kthook_naked>), sizeof(std::uintptr_t));
        jump_gen->L(ret_addr);

        jump_gen->cmp(rax, -1);
        jump_gen->je(jump_out);

        jump_gen->cmp(rax, hook_size);
        jump_gen->jl(jump_in_trampoline);

        jump_gen->L(jump_out);

        jump_gen->mov(rsp, reinterpret_cast<std::uintptr_t>(&context.rbx));
        jump_gen->pop(rbx);
        jump_gen->pop(rcx);
        jump_gen->pop(rdx);
        jump_gen->add(rsp, 8);
        jump_gen->pop(rbp);
        jump_gen->pop(rsi);
        jump_gen->pop(rdi);
        jump_gen->pop(r8);
        jump_gen->pop(r9);
        jump_gen->pop(r10);
        jump_gen->pop(r11);
        jump_gen->pop(r12);
        jump_gen->pop(r13);
        jump_gen->pop(r14);
        jump_gen->pop(r15);

        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)]);
        jump_gen->mov(rsp, rax);
        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
        jump_gen->push(rax);
        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
        jump_gen->sub(rsp, sizeof(cpu_ctx::eflags));
        jump_gen->popfq();

        jump_gen->ret();

        jump_gen->L(jump_in_trampoline);

        jump_gen->mov(rsp, rax);
        jump_gen->mov(rax, skip_bytes);
        jump_gen->add(rax, rsp);

        jump_gen->mov(ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)], rax);

        jump_gen->mov(rsp, reinterpret_cast<std::uintptr_t>(&context.rbx));
        jump_gen->pop(rbx);
        jump_gen->pop(rcx);
        jump_gen->pop(rdx);
        jump_gen->add(rsp, 8);
        jump_gen->pop(rbp);
        jump_gen->pop(rsi);
        jump_gen->pop(rdi);
        jump_gen->pop(r8);
        jump_gen->pop(r9);
        jump_gen->pop(r10);
        jump_gen->pop(r11);
        jump_gen->pop(r12);
        jump_gen->pop(r13);
        jump_gen->pop(r14);
        jump_gen->pop(r15);

        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rsp)]);
        jump_gen->mov(rsp, rax);
        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&last_return_address)]);
        jump_gen->push(rax);
        jump_gen->mov(rax, ptr[reinterpret_cast<std::uintptr_t>(&context.rax)]);
        jump_gen->sub(rsp, sizeof(cpu_ctx::eflags));
        jump_gen->popfq();

        jump_gen->ret();

        jump_gen->L(skip_bytes);

        detail::create_trampoline(info.hook_address, jump_gen);

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
                this->hook_size = detail::detect_hook_size(info.hook_address);
                this->relay_jump = generate_relay_jump();

                detail::frozen_threads threads;

                if (!detail::freeze_threads(threads))
                    return false;
                if (!set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                     detail::MemoryProt::PROTECT_RWE))
                    return false;
                info.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                std::memcpy(info.original_code.get(), reinterpret_cast<void*>(info.hook_address), this->hook_size);
                std::uintptr_t relative =
                    detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
                std::memcpy(&patch, reinterpret_cast<void*>(info.hook_address), sizeof(patch));
                if (patch.opcode != 0xE8) {
                    patch.opcode = 0xE9;
                }
                patch.operand = static_cast<std::uint32_t>(relative);
                std::memcpy(reinterpret_cast<void*>(info.hook_address), &patch, sizeof(patch));
                memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                       this->hook_size - sizeof(patch));
                if (!detail::set_memory_prot(reinterpret_cast<void*>(info.hook_address), this->hook_size,
                                             detail::MemoryProt::PROTECT_RE))
                    return false;

                if (!detail::unfreeze_threads(threads))
                    return false;
            } else {
                jump_gen->rewrite(0, original, 8);
            }
        } else if (relay_jump) {
            std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
            jump_gen->rewrite(0, 0x9090909090909090, 8);
        }
        if (jump_gen.get()) detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
        return true;
    }

    bool create_generators() {
        void* alloc = detail::try_alloc_near(info.hook_address);
        if (alloc == nullptr) return false;
        void* jump_alloc = alloc;
        auto trampoline_alloc = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(jump_alloc) + 0x800);
        jump_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, jump_alloc,
                                                          &detail::default_jmp_allocator);
        trampoline_gen = std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, trampoline_alloc,
                                                                &detail::default_trampoline_allocator);
        return true;
    }

    hook_info info;
    cb_type callback{};
    std::size_t hook_size{0};
    std::uint64_t original{0};

    mutable std::uintptr_t last_return_address{0};
    mutable cpu_ctx context{};

    std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
    std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;

    const std::uint8_t* relay_jump{nullptr};
    bool installed{false};
};
} // namespace kthook

#endif  // KTHOOK_IMPL_HPP_
