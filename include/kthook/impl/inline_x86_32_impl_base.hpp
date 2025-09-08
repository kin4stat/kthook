#ifndef KTHOOK_INLINE_X86_32_IMPL_HPP_
#define KTHOOK_INLINE_X86_32_IMPL_HPP_

namespace kthook {
template <typename FuncSig, template<typename> typename Traits, typename Derived>
class win_x86_32_inline_impl_base : public utils::dependent_stack_holder<Traits<FuncSig>::allow_recursive_calls,
                                                                         arch::detail::ctx_storage<Traits<FuncSig>>> {
protected:
  using HookTraits = Traits<FuncSig>;
  using StackHolder = utils::dependent_stack_holder<Traits<FuncSig>::allow_recursive_calls,
                                                    arch::detail::ctx_storage<Traits<FuncSig>>>;

  struct default_args {
  };

  struct args {
    std::uintptr_t address;
  };

  struct set_dest_args {
    std::uintptr_t address;
  };

  win_x86_32_inline_impl_base(default_args args) : info(0, nullptr) {
    make_ctx_storage();
  }

  win_x86_32_inline_impl_base(args args) : info(args.address, nullptr) {
    make_ctx_storage();
  }

  win_x86_32_inline_impl_base(const win_x86_32_inline_impl_base& other) = delete;
  win_x86_32_inline_impl_base(win_x86_32_inline_impl_base&& other) noexcept = default;
  win_x86_32_inline_impl_base& operator=(const win_x86_32_inline_impl_base& other) = delete;
  win_x86_32_inline_impl_base& operator=(win_x86_32_inline_impl_base&& other) noexcept = default;

  ~win_x86_32_inline_impl_base() {
    remove();
  }

  template <typename Hook>
  error_code_t install() {
    if (installed) return error_code_t::kAlreadyInstalled;
    if (info.hook_address == 0) return error_code_t::kHookAddressNotValid;
    if (!platform::check_is_executable(info.hook_address_ptr)) return error_code_t::kHookLocationNotExecutable;

    hook_size = disasm::detect_hook_size(info.hook_address);
    if (hook_size < sizeof(disasm::JMP_REL)) {
    }

    if (!arch::make_trampoline(info.hook_address, trampoline_gen, hook_size))
      return error_code_t::kTrampolineCreationError;
    platform::flush_instruction_cache(info.hook_address_ptr, hook_size);
    if (enable_hook<Hook>() != error_code_t::kOk) return error_code_t::kHookInstallationFailure;
    installed = true;
    return error_code_t::kOk;
  }

  /**
   * Removes the hook, but keeps trampoline, so if there any other hooks, process won't crash
   * @return error, if occurred
   */
  error_code_t remove() {
    if (!installed) return error_code_t::kNotInstalled;
    installed = disable_hook() != error_code_t::kOk;
    if (installed) return error_code_t::kHookRemoveFailure;
    return error_code_t::kOk;
  }

  /**
   * Removes the hook completely, returning the instructions that were there before
   * @return error, if occurred
   */
  error_code_t reset() {
    if (!platform::set_memory_prot(info.hook_address_ptr, hook_size, platform::MemoryProt::PROTECT_RW)) {
      return error_code_t::kMemoryProtectionFailure;
    }
    std::memcpy(info.hook_address_ptr, info.original_code.get(), hook_size);
    if (!platform::set_memory_prot(info.hook_address_ptr, hook_size, platform::MemoryProt::PROTECT_RW)) {
      return error_code_t::kMemoryProtectionFailure;
    }
    installed = false;

    jump_gen->reset();
    trampoline_gen->reset();
    relay_jump = nullptr;
    original = 0;
    info.original_code.reset();

    return error_code_t::kOk;
  }

  /**
   * Sets the new hook address.
   *
   * If the hook was installed before, it calls @p reset, and then @p install with a new address
   * @param args see @p set_dest_args
   */
  template <typename Hook>
  error_code_t set_dest(set_dest_args args) {
    error_code_t code = error_code_t::kOk;
    const bool was_installed = installed;
    if (installed) {
      code = reset();
    }

    if (code != error_code_t::kOk) {
      return code;
    }

    info.hook_address = args.address;

    if (was_installed) {
      code = enable_hook<Hook>();
    }

    return code;
  }

  /**
   * 
   * @return boolean was the hook installed before
   */
  bool is_installed() const noexcept {
    return installed;
  }

protected:
  void make_ctx_storage() {
    if constexpr (Traits<FuncSig>::allow_recursive_calls) {
      // make empty slot for first call
      this->ctx_storage_.emplace();
    }
  }

  /**
   * Generates asm for saving context and forwarding hook interface to callback
   * @return pointer to generated relay between hook and original function
   */
  template <typename Hook>
  const void* generate_relay_jump() {
    using namespace Xbyak::util;

    const auto hook_address = info.hook_address;
    Xbyak::Label UserCode;
    jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
    jump_gen->nop(3);
    arch::make_trampoline(hook_address, jump_gen, hook_size);
    jump_gen->L(UserCode);

    auto to_uintptr = [](auto v) -> std::uintptr_t {
      return reinterpret_cast<std::uintptr_t>(v);
    };

    auto& ctx_storage = to_uintptr(utils::get_frame_ctx_storage(this));

    std::uintptr_t _storage0 = to_uintptr(ctx_storage._storage0.get());
    if constexpr (HookTraits::save_flags) {
      std::uintptr_t _storage1 = to_uintptr(ctx_storage._storage1.get());
      using storage_t = arch::detail::storage_cpu_ctx_flags<true>;

      const std::uintptr_t storage = to_uintptr(arch::detail::get_storage<storage_t>(ctx_storage));

      jump_gen->pushfd();
      jump_gen->mov(ptr[_storage0], eax);
      jump_gen->mov(ptr[_storage1], ecx);
      jump_gen->mov(eax, storage);
      jump_gen->mov(ecx, ptr[esp]);
      jump_gen->mov(ptr[eax], ecx);
      jump_gen->mov(eax, ptr[_storage0]);
      jump_gen->mov(ecx, ptr[_storage1]);
      jump_gen->add(esp, 4);
    }

    if constexpr (HookTraits::save_segment_regs) {
      std::uintptr_t _storage1 = to_uintptr(ctx_storage._storage1.get());
      using storage_t = arch::detail::storage_cpu_ctx_segment_regs<true>;

      const std::uintptr_t storage = to_uintptr(arch::detail::get_storage<storage_t>(ctx_storage));

      constexpr std::array segments{cs, ds, es, fs, gs, ss};

      jump_gen->mov(ptr[_storage0], eax);
      jump_gen->mov(ptr[_storage1], ecx);

      jump_gen->mov(ecx, storage);

      for (auto& seg : segments) {
        jump_gen->mov(eax, seg);
        jump_gen->mov(ptr[ecx], eax);
        jump_gen->add(ecx, sizeof(std::uint16_t));
      }

      jump_gen->mov(eax, ptr[_storage0]);
      jump_gen->mov(ecx, ptr[_storage1]);
    }

    if constexpr (HookTraits::save_regs) {
      using storage_t = arch::detail::storage_cpu_ctx_int<true>;

      const std::uintptr_t storage = to_uintptr(arch::detail::get_storage<storage_t>(ctx_storage));
      const std::uintptr_t esp_offset = ((static_cast<unsigned>(REG::esp) >> 4) & 0b1111) * 4;

      jump_gen->mov(ptr[_storage0], esp);

      jump_gen->mov(esp, storage);
      jump_gen->pushad();

      jump_gen->mov(esp, ptr[_storage0]);
      jump_gen->mov(ptr[storage + esp_offset], esp);
    }

    if constexpr (HookTraits::save_x87) {
      using storage_t = arch::detail::storage_cpu_ctx_x87<true>;

      constexpr std::uint8_t code[] = {0x0f, 0xae, 0x00}; // fxsave [eax]
      const std::uintptr_t storage = to_uintptr(arch::detail::get_storage<storage_t>(ctx_storage));

      jump_gen->mov(ptr[_storage0], eax);

      jump_gen->mov(eax, ptr[storage]);
      jump_gen->db(code, sizeof(code));
      jump_gen->mov(eax, ptr[_storage0]);
    }

    {
      const std::uintptr_t storage = to_uintptr(&ctx_storage.last_return_address);

      jump_gen->mov(ptr[_storage0], eax);
      jump_gen->pop(eax);
      jump_gen->mov(ptr[storage], eax);
      jump_gen->push(eax);
      jump_gen->mov(eax, ptr[_storage0]);
    }

    static_cast<Derived>(this)->template generate_relay_jump_impl<Hook>();
    platform::flush_instruction_cache(jump_gen->getCode(), jump_gen->getSize());
    return jump_gen->getCode();
  }

  template <typename Hook>
  error_code_t enable_hook() {
    if (!this->relay_jump) {
      disasm::hook_patch patch;

      this->relay_jump = static_cast<const std::uint8_t*>(generate_relay_jump<Hook>());

      platform::frozen_threads threads;

      if constexpr (HookTraits::freeze_threads)
        if (!platform::freeze_threads(threads))
          return error_code_t::kThreadFreezeError;

      auto old_prot = platform::get_memory_prot(reinterpret_cast<void*>(info.hook_address));
      if (!platform::set_memory_prot(info.hook_address_ptr, this->hook_size, platform::MemoryProt::PROTECT_RWE))
        return error_code_t::kMemoryProtectionFailure;

      info.original_code = std::make_unique<std::uint8_t[]>(this->hook_size);
      std::memcpy(info.original_code.get(), info.hook_address_ptr, this->hook_size);

      uintptr_t relative =
          platform::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
      std::memcpy(&patch, info.hook_address_ptr, sizeof(patch));
      if (patch.opcode != 0xE8) {
        patch.opcode = 0xE9;
      }

      patch.operand = relative;
      std::memcpy(info.hook_address_ptr, &patch, sizeof(patch));

      std::memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                  this->hook_size - sizeof(patch));

      if (!platform::set_memory_prot(info.hook_address_ptr, this->hook_size, old_prot))
        return error_code_t::kMemoryProtectionFailure;

      if constexpr (HookTraits::freeze_threads)
        if (!platform::unfreeze_threads(threads))
          return error_code_t::kThreadFreezeError;
    } else {
      jump_gen->rewrite(0, original, 8);
    }
    platform::flush_instruction_cache(relay_jump, jump_gen->getSize());
    return error_code_t::kOk;
  }

  error_code_t disable_hook() {
    if (relay_jump) {
      std::memcpy(&original, relay_jump, sizeof(original));
      jump_gen->rewrite(0, 0x9090909090909090, 8);
    }
    platform::flush_instruction_cache(relay_jump, jump_gen->getSize());
    return error_code_t::kOk;
  }

  arch::hook_info info;
  std::size_t hook_size{0};
  std::uint64_t original{0};

  std::unique_ptr<Xbyak::CodeGenerator> jump_gen{xbyak_wrap::get_jmp_generator()};
  std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen{std::make_unique<Xbyak::CodeGenerator>()};

  const std::uint8_t* relay_jump{nullptr};

  bool installed = false;
};
}

#endif // KTHOOK_INLINE_X86_32_IMPL_HPP_