#ifndef KTHOOK_IMPL_HPP_
#define KTHOOK_IMPL_HPP_

namespace kthook {
#pragma pack(push, 1)
    struct CPU_Context {
        std::uint32_t edi;
        std::uint32_t esi;
        std::uint32_t ebp;
        std::uint32_t esp;
        std::uint32_t ebx;
        std::uint32_t edx;
        std::uint32_t ecx;
        std::uint32_t eax;
        struct EFLAGS {
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
        } flags;
        std::uint8_t align;
    };
#pragma pack(pop)

	namespace detail {
        inline bool create_trampoline(std::uintptr_t hook_address, const std::unique_ptr<Xbyak::CodeGenerator>& trampoline_gen) {
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

            std::size_t trampoline_size = 0;
            std::size_t op_copy_size = 0;
            void* op_copy_src = nullptr;
            std::uintptr_t current_address = hook_address;
            std::uintptr_t max_jmp_ref = 0;
            bool finished = false;

            while (!finished) {
                detail::hde hs;
                std::size_t op_copy_size = hde_disasm(reinterpret_cast<void*>(current_address), &hs);
                if (hs.flags & F_ERROR)
                    return false;
                op_copy_src = reinterpret_cast<void*>(current_address);
                if (current_address - hook_address >= sizeof(call)) {
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
                    *pRelAddr = (std::uint32_t)((current_address + hs.len + (std::int32_t)hs.disp.disp32) - ((std::uintptr_t)(trampoline_gen->getCurr()) + hs.len));

                    // Complete the function if JMP (FF /4).
                    if (hs.opcode == 0xFF && hs.modrm_reg == 4)
                        finished = true;
                }
#endif
                // Relative Call
                else if (hs.opcode == 0xE8)
                {
                    std::uintptr_t call_destination = detail::restore_absolute_address(current_address, hs.imm.imm32, hs.len);
#ifdef KTHOOK_64
                    call.address = call_destination;
#else
                    call.operand = detail::get_relative_address(call_destination,
                        reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(call));
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
#ifdef KTHOOK_64
                        jmp.address = jmp_destination;
#else
                        jmp.operand = detail::get_relative_address(jmp_destination,
                            reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jmp));
#endif
                        op_copy_src = &jmp;
                        op_copy_size = sizeof(jmp);

                        // Exit the function if it is not in the branch.
                        finished = (hook_address >= max_jmp_ref)
#ifdef KTHOOK_64
                            && (current_address - hook_address > sizeof(call))
#endif                    
                            ;
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
#ifdef KTHOOK_64
                        // Invert the condition in x64 mode to simplify the conditional jump logic.
                        jcc.opcode = 0x71 ^ cond;
                        jcc.address = jmp_destination;
#else
                        jcc.opcode1 = 0x80 | cond;
                        jcc.operand = detail::get_relative_address(jmp_destination,
                            reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jcc));
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
	}

    template<typename T>
    class kthook_simple {
        // static_assert(std::is_member_function_pointer_v<T> ||
        //     std::is_function_v<std::remove_pointer_t<T>> ||
        //     std::is_function_v<T>, "T is not member function pointer/function pointer/function");

        using function = detail::traits::function_traits<T>;
        using Args = typename function::args;
        using Ret = typename function::return_type;
        using function_ptr = detail::traits::function_connect_ptr_t<function::convention, Ret, Args>;
        using cb_type = std::function<detail::traits::function_connect_t<Ret, detail::traits::tuple_cat_t<const kthook_simple&, Args>>>;

        struct hook_info {
            std::uintptr_t hook_address;
            std::unique_ptr<unsigned char[]> original_code;

            hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c) : hook_address(a), original_code(std::move(c)) {}
            hook_info(std::uintptr_t a) : hook_address(a), original_code(nullptr) {}
        };

        friend struct detail::relay_generator<kthook_simple, function::convention, Ret, Args>;
    public:
        kthook_simple() {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
        }

        kthook_simple(std::uintptr_t destination, cb_type callback_, bool force_enable = true) : callback(std::move(callback_)) {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            hooks.emplace_back(destination, nullptr);
            if (force_enable) {
                install();
            }
        }

        kthook_simple(std::uintptr_t destination) {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            hooks.emplace_back(destination, nullptr);
        }

        kthook_simple(void* destination) : kthook_simple(reinterpret_cast<std::uintptr_t>(destination)) {}

        kthook_simple(void* destination, cb_type callback, bool force_enable = true) :
            kthook_simple(reinterpret_cast<std::uintptr_t>(destination), callback, force_enable) {}

        template<typename Ptr>
        kthook_simple(Ptr* destination, cb_type callback_, bool force_enable = true) : kthook_simple(reinterpret_cast<void*>(destination), callback_, force_enable) {}

        // WIP
        /*kthook_simple(std::initializer_list<std::uintptr_t> addresses, cb_type callback_, bool force_enable = true) : hooks(addresses), callback(callback_) {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            if (force_enable) {
                install();
            }
        }

        kthook_simple(std::initializer_list<void*> addresses, cb_type callback_, bool force_enable = true) : callback(callback_) {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            for (auto&& address : addresses) {
                hooks.emplace_back(reinterpret_cast<std::uintptr_t>(address), nullptr);
            }
            if (force_enable) {
                install();
            }
        }*/

        ~kthook_simple() {
            remove();
        }

        bool install() {
            if (!detail::check_is_executable(reinterpret_cast<void*>(hooks.begin()->hook_address))) return false;
            if (!detail::create_trampoline(hooks.begin()->hook_address, trampoline_gen)) return false;
            if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
            if (!patch_hook(true)) return false;
            return true;
        }

        bool remove() {
            return patch_hook(false);
        }

        bool reset() {
            for (auto& hook : hooks) {
                if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RWE)) return false;
                std::memcpy(reinterpret_cast<void*>(hook.hook_address), hook.original_code.get(), this->hook_size);
                if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RE)) return false;
            }
            hooks.clear();
        }

        void set_cb(cb_type callback_) {
            callback = std::move(callback_);
        }

        void set_dest(std::uintptr_t address) {
            hooks.clear();
            hooks.emplace_back(address, nullptr);
        }

        void set_dest(void* address) {
            set_dest(reinterpret_cast<std::uintptr_t>(address));
        }

        std::uintptr_t get_return_address() const {
            return *last_return_address;
        }

        std::uintptr_t* get_return_address_ptr() const {
            return last_return_address;
        }

        const CPU_Context& get_context() const {
            return context;
        }

        const function_ptr get_trampoline() const {
            return reinterpret_cast<const function_ptr>(trampoline_gen->getCode());
        }

    private:
        template <typename T>
        T get_trampoline() {
            return reinterpret_cast<T>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
        }

        const std::uint8_t* generate_relay_jump() {
            using namespace Xbyak::util;

            auto hook_address = hooks.begin()->hook_address;
#pragma pack(push, 1)
            struct {
                std::uint8_t opcode;
                std::uint32_t operand;
            } info;

            std::memcpy(&info, reinterpret_cast<void*>(hook_address), sizeof(info));
#pragma pack(pop)

            Xbyak::Label UserCode;
            jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
            jump_gen->nop(3);
            jump_gen->db(trampoline_gen->getCode(), trampoline_gen->getSize());
            jump_gen->L(UserCode);
            if constexpr (std::is_function_v<T>) {
                static_assert(false, "WIP");
                size_t args_offset = function::args_count * 4 + 4;
                for (auto i = 0u; i < function::args_count; i++) {
                    jump_gen->push(ptr[esp + args_offset]);
                }
            }
            else {
                jump_gen->mov(ptr[&last_return_address], esp);
                jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.align));
                jump_gen->pushfd();
                jump_gen->pushad();
                jump_gen->mov(esp, ptr[&last_return_address]);
                jump_gen->mov(ptr[&context.esp], esp);
                if constexpr (function::convention != detail::traits::cconv::ccdecl) {
                    jump_gen->pop(eax);
                }
                if constexpr (function::convention == detail::traits::cconv::cthiscall) {
                    jump_gen->push(ecx);
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                auto relay_ptr = &detail::relay_generator<kthook_simple, function::convention, typename function::return_type, typename function::args>::relay;
                if constexpr (function::convention == detail::traits::cconv::ccdecl) {
                    jump_gen->call(relay_ptr);
                    jump_gen->add(esp, 4);
                    jump_gen->ret();
                }
                else {
                    jump_gen->push(eax);
                    jump_gen->jmp(relay_ptr);
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
                    this->relay_jump = generate_relay_jump();
                    for (auto& hook : hooks) {
                        this->hook_size = detail::detect_hook_size(hook.hook_address);
                        if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RWE)) return false;
                        hook.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                        std::memcpy(hook.original_code.get(), reinterpret_cast<void*>(hook.hook_address), this->hook_size);
                        uintptr_t relative = detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), hook.hook_address);
                        std::memcpy(&patch, reinterpret_cast<void*>(hook.hook_address), sizeof(patch));
                        if (patch.opcode != 0xE8) {
                            patch.opcode = 0xE9;
                        }
                        patch.operand = relative;
                        std::memcpy(reinterpret_cast<void*>(hook.hook_address), &patch, sizeof(patch));
                        memset(reinterpret_cast<void*>(hook.hook_address + sizeof(patch)), 0x90, this->hook_size - sizeof(patch));
                        if (!detail::set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RE)) return false;
                    }
                }
                else {
                    jump_gen->rewrite(0, original, 8);
                }
            }
            else if (relay_jump) {
                std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
                jump_gen->rewrite(0, 0x9090909090909090, 8);
            }
            detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
            return true;
        }

        cb_type callback;
        std::vector<hook_info> hooks;
        std::uintptr_t* last_return_address;
        std::size_t hook_size;
        std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
        std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;
        std::uint64_t original;
        const std::uint8_t* relay_jump;
        mutable CPU_Context context;
    };

    template<typename T>
    class kthook_signal {
        // static_assert(std::is_member_function_pointer_v<T> ||
        //     std::is_function_v<std::remove_pointer_t<T>> ||
        //     std::is_function_v<T>, "T is not member function pointer/function pointer/function");

        template<class T, typename Tuple, typename Enable = void>
        struct on_after_type;

        template<class T, typename... Ts>
        struct on_after_type<T, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<T>>::type> {
            using type = ktsignal::ktsignal_threadsafe<void(const kthook_signal&, std::add_lvalue_reference_t<Ts>...)>;
        };

        template<class T, typename... Ts>
        struct on_after_type<T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
            using type = ktsignal::ktsignal_threadsafe<void(const kthook_signal&, T&, std::add_lvalue_reference_t<Ts>...)>;
        };

        template<class T, typename Tuple, typename Enable = void>
        struct on_before_type;

        template<class T, typename... Ts>
        struct on_before_type<T, std::tuple<Ts...>, typename std::enable_if<std::is_void_v<T>>::type> {
            using type = ktsignal::ktsignal_threadsafe<bool(const kthook_signal&, std::add_lvalue_reference_t<Ts>...)>;
        };

        template<class T, typename... Ts>
        struct on_before_type<T, std::tuple<Ts...>, typename std::enable_if<!std::is_void_v<T>>::type> {
            using type = ktsignal::ktsignal_threadsafe<std::optional<T>(const kthook_signal&, std::add_lvalue_reference_t<Ts>...)>;
        };

        using function = detail::traits::function_traits<T>;
        using Args = detail::traits::convert_refs_t<typename function::args>;
        using Ret = detail::traits::convert_ref_t<typename function::return_type>;
        using function_ptr = typename detail::traits::function_connect_ptr_t<function::convention, Ret, Args>;
        using before_t = typename on_before_type<Ret, Args>::type;
        using after_t = typename on_after_type<Ret, Args>::type;

        struct hook_info {
            std::uintptr_t hook_address;
            std::unique_ptr<unsigned char[]> original_code;

            hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c) : hook_address(a), original_code(std::move(c)) {}
            hook_info(std::uintptr_t a) : hook_address(a), original_code(nullptr) {}
        };

        friend struct detail::signal_relay_generator<kthook_signal, function::convention, Ret, Args>;
    public:
        kthook_signal() {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
        }

        kthook_signal(std::uintptr_t destination, bool force_enable = true) {
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            hooks.emplace_back(destination, nullptr);
            if (force_enable) {
                install();
            }
        }

        kthook_signal(void* destination, bool force_enable = true) :
            kthook_signal(reinterpret_cast<std::uintptr_t>(destination), force_enable) {}

        template<typename Ptr>
        kthook_signal(Ptr* destination, bool force_enable = true) : kthook_signal(reinterpret_cast<void*>(destination), force_enable) {}

        // WIP
        /*kthook_signal(std::initializer_list<std::uintptr_t> addresses, bool force_enable = true) {
            for (auto&& address : addresses) {
                hooks.emplace_back(address, nullptr);
            }
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            if (force_enable) {
                install();
            }
        }

        kthook_signal(std::initializer_list<void*> addresses, bool force_enable = true){
            trampoline_gen = std::make_unique<Xbyak::CodeGenerator>();
            jump_gen = std::make_unique<Xbyak::CodeGenerator>();
            for (auto&& address : addresses) {
                hooks.emplace_back(reinterpret_cast<std::uintptr_t>(address), nullptr);
            }
            if (force_enable) {
                install();
            }
        }*/

        ~kthook_signal() {
            remove();
        }

        bool install() {
            if (!detail::check_is_executable(reinterpret_cast<void*>(hooks.begin()->hook_address))) return false;
            if (!detail::create_trampoline(hooks.begin()->hook_address, trampoline_gen)) return false;
            if (!detail::flush_intruction_cache(trampoline_gen->getCode(), trampoline_gen->getSize())) return false;
            if (!patch_hook(true)) return false;
            return true;
        }

        bool remove() {
            return patch_hook(false);
        }

        bool reset() {
            for (auto& hook : hooks) {
                if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RWE)) return false;
                std::memcpy(reinterpret_cast<void*>(hook.hook_address), hook.original_code.get(), this->hook_size);
                if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RE)) return false;
            }
            hooks.clear();
        }

        void set_dest(std::uintptr_t address) {
            hooks.clear();
            hooks.emplace_back(address, nullptr);
        }

        void set_dest(void* address) {
            set_dest(reinterpret_cast<std::uintptr_t>(address));
        }

        std::uintptr_t get_return_address() const {
            return *last_return_address;
        }

        std::uintptr_t* get_return_address_ptr() const {
            return last_return_address;
        }

        const CPU_Context& get_context() const {
            return context;
        }

        const function_ptr get_trampoline() {
            return reinterpret_cast<const function_ptr>(trampoline_gen->getCode());
        }

        before_t before;
        after_t after;
    private:
        template <typename T>
        T get_trampoline() {
            return reinterpret_cast<T>(const_cast<std::uint8_t*>(trampoline_gen->getCode()));
        }

        const std::uint8_t* generate_relay_jump() {
            using namespace Xbyak::util;

            auto hook_address = hooks.begin()->hook_address;
#pragma pack(push, 1)
            struct {
                std::uint8_t opcode;
                std::uint32_t operand;
            } info;

            std::memcpy(&info, reinterpret_cast<void*>(hook_address), sizeof(info));
#pragma pack(pop)

            Xbyak::Label UserCode;
            jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
            jump_gen->nop(3);
            jump_gen->db(trampoline_gen->getCode(), trampoline_gen->getSize());
            jump_gen->L(UserCode);
            if constexpr (std::is_function_v<T>) {
                static_assert(false, "WIP");
                size_t args_offset = function::args_count * 4 + 4;
                for (auto i = 0u; i < function::args_count; i++) {
                    jump_gen->push(ptr[esp + args_offset]);
                }
            }
            else {
                jump_gen->mov(ptr[&last_return_address], esp);
                jump_gen->mov(esp, reinterpret_cast<std::uintptr_t>(&context.align));
                jump_gen->pushfd();
                jump_gen->pushad();
                jump_gen->mov(esp, ptr[&last_return_address]);
                jump_gen->mov(ptr[&context.esp], esp);
                if constexpr (function::convention != detail::traits::cconv::ccdecl) {
                    jump_gen->pop(eax);
                }
                if constexpr (function::convention == detail::traits::cconv::cthiscall) {
                    jump_gen->push(ecx);
                }
                jump_gen->push(reinterpret_cast<std::uintptr_t>(this));
                auto relay_ptr = &detail::signal_relay_generator<kthook_signal, function::convention, Ret, Args>::relay;
                if constexpr (function::convention == detail::traits::cconv::ccdecl) {
                    jump_gen->call(relay_ptr);
                    jump_gen->add(esp, 4);
                    jump_gen->ret();
                }
                else {
                    jump_gen->push(eax);
                    jump_gen->jmp(relay_ptr);
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
                    this->relay_jump = generate_relay_jump();
                    for (auto& hook : hooks) {
                        this->hook_size = detail::detect_hook_size(hook.hook_address);
                        if (!set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RWE)) return false;
                        hook.original_code = std::make_unique<unsigned char[]>(this->hook_size);
                        std::memcpy(hook.original_code.get(), reinterpret_cast<void*>(hook.hook_address), this->hook_size);
                        uintptr_t relative = detail::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), hook.hook_address);
                        std::memcpy(&patch, reinterpret_cast<void*>(hook.hook_address), sizeof(patch));
                        if (patch.opcode != 0xE8) {
                            patch.opcode = 0xE9;
                        }
                        patch.operand = relative;
                        std::memcpy(reinterpret_cast<void*>(hook.hook_address), &patch, sizeof(patch));
                        memset(reinterpret_cast<void*>(hook.hook_address + sizeof(patch)), 0x90, this->hook_size - sizeof(patch));
                        if (!detail::set_memory_prot(reinterpret_cast<void*>(hook.hook_address), this->hook_size, detail::MemoryProt::PROTECT_RE)) return false;
                    }
                }
                else {
                    jump_gen->rewrite(0, original, 8);
                }
            }
            else if (relay_jump) {
                std::memcpy(reinterpret_cast<void*>(&original), relay_jump, sizeof(original));
                jump_gen->rewrite(0, 0x9090909090909090, 8);
            }
            detail::flush_intruction_cache(relay_jump, jump_gen->getSize());
            return true;
        }

        std::vector<hook_info> hooks;
        std::uintptr_t* last_return_address;
        std::size_t hook_size;
        std::unique_ptr<Xbyak::CodeGenerator> jump_gen;
        std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen;
        std::uint64_t original;
        const std::uint8_t* relay_jump;
        mutable CPU_Context context;
    };
}

#endif //KTHOOK_IMPL_HPP_