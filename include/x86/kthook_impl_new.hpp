#ifndef KTHOOK_IMPL_HPP_
#define KTHOOK_IMPL_HPP_

namespace kthook {
std::unique_ptr<Xbyak::CodeGenerator> get_jmp_generator() {
  return std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, nullptr, &utils::default_jmp_allocator);
}

struct create_trampoline_result {
  std::size_t available_size;
};

template <typename FuncSig, template<typename> typename Traits>
class hook
    : public Traits<FuncSig>,
      public detail::dependent_stack_holder<Traits<FuncSig>::allow_recursive_calls,
                                            detail::ctx_storage<Traits<FuncSig>>> {
public:
  using HookTraits = Traits<FuncSig>;
  using FunctionSignature = FuncSig;

  hook()
    : info(0, nullptr) {
  }

  hook(std::uintptr_t destination, bool force_enable = false)
    : info(destination, nullptr) {
    if (force_enable) {
      install();
    }
  }

  hook(void* destination, bool force_enable = false)
    : hook(reinterpret_cast<std::uintptr_t>(destination), force_enable) {
  }

  template <typename Ptr>
  hook(Ptr* destination, bool force_enable = false)
    : hook(reinterpret_cast<void*>(destination), force_enable) {
  }

  ~hook() {
    remove();
  }

  kthook_error_code_t install() {
    if (installed) return kthook_error_code_t::kAlreadyInstalled;
    if (info.hook_address == 0) return kthook_error_code_t::kHookAddressNotValid;
    if (!utils::check_is_executable(info.hook_address_ptr)) return kthook_error_code_t::kHookLocationNotExecutable;

    hook_size = utils::detect_hook_size(info.hook_address);
    if (hook_size < sizeof(detail::JMP_REL)) {
    }

    if (!detail::create_trampoline(info.hook_address, trampoline_gen, hook_size))
      return
          kthook_error_code_t::kTrampolineCreationError;
    utils::flush_instruction_cache(info.hook_address_ptr, hook_size);
    if (patch_hook(true) != kthook_error_code_t::kOk) return kthook_error_code_t::kHookInstallationFailure;
    installed = true;
    return kthook_error_code_t::kOk;
  }

  kthook_error_code_t remove() {
    if (!installed) return kthook_error_code_t::kNotInstalled;
    installed = patch_hook(false) != kthook_error_code_t::kOk;
    if (installed) return kthook_error_code_t::kHookRemoveFailure;
    return kthook_error_code_t::kOk;
  }

  kthook_error_code_t reset() {
    if (!utils::set_memory_prot(info.hook_address_ptr, hook_size, utils::MemoryProt::PROTECT_RW)) {
      return kthook_error_code_t::kMemoryProtectionFailure;
    }
    std::memcpy(info.hook_address_ptr, info.original_code.get(), hook_size);
    if (!utils::set_memory_prot(info.hook_address_ptr, hook_size, utils::MemoryProt::PROTECT_RW)) {
      return kthook_error_code_t::kMemoryProtectionFailure;
    }
    installed = false;

    jump_gen->reset();
    trampoline_gen->reset();
    relay_jump = nullptr;
    original = 0;
    info.original_code.reset();

    return kthook_error_code_t::kOk;
  }

  void set_dest(std::uintptr_t address) {
    const bool was_installed = installed;
    if (installed) {
      reset();
    }

    info.hook_address = address;

    if (was_installed) {
      install();
    }
  }

  void set_dest(void* address) {
    set_dest(reinterpret_cast<std::uintptr_t>(address));
  }

  bool is_installed() const noexcept {
    return installed;
  }

private:
  const void* generate_relay_jump() {
    using namespace Xbyak::util;

    const auto hook_address = info.hook_address;
    Xbyak::Label UserCode;
    jump_gen->jmp(UserCode, Xbyak::CodeGenerator::LabelType::T_NEAR);
    jump_gen->nop(3);
    detail::create_trampoline(hook_address, jump_gen, hook_size);
    jump_gen->L(UserCode);

    auto to_uintptr = [](auto v) -> std::uintptr_t {
      return reinterpret_cast<std::uintptr_t>(v);
    };

    std::uintptr_t _storage0 = to_uintptr(ctx_storage._storage0.get());
    if constexpr (HookTraits::save_flags) {
      std::uintptr_t _storage1 = to_uintptr(ctx_storage._storage1.get());
      using storage_t = detail::storage_cpu_ctx_flags<true>;

      const std::uintptr_t storage = to_uintptr(detail::get_storage<storage_t>(ctx_storage));

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
      using storage_t = detail::storage_cpu_ctx_segment_regs<true>;

      const std::uintptr_t storage = to_uintptr(detail::get_storage<storage_t>(ctx_storage));

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
      using storage_t = detail::storage_cpu_ctx_int<true>;

      const std::uintptr_t storage = to_uintptr(detail::get_storage<storage_t>(ctx_storage));
      const std::uintptr_t esp_offset = ((static_cast<unsigned>(REG::esp) >> 4) & 0b1111) * 4;

      jump_gen->mov(ptr[_storage0], esp);

      jump_gen->mov(esp, storage);
      jump_gen->pushad();

      jump_gen->mov(esp, ptr[_storage0]);
      jump_gen->mov(ptr[storage + esp_offset], esp);
    }

    if constexpr (HookTraits::save_x87) {
      using storage_t = detail::storage_cpu_ctx_x87<true>;

      constexpr std::uint8_t code[] = {0x0f, 0xae, 0x00}; // fxsave [eax]
      const std::uintptr_t storage = to_uintptr(detail::get_storage<storage_t>(ctx_storage));

      jump_gen->mov(ptr[_storage0], eax);

      jump_gen->mov(eax, storage);
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

    constexpr auto cconv = HookTraits::function::convention;
    using ret_t = typename HookTraits::hook_ret_t;
    using args_t = typename HookTraits::hook_args_t;

    if constexpr (HookTraits::use_thread_locals) {
      const auto relay = reinterpret_cast<void*>(
        detail::safe_relay::relay_generator<hook, cconv, ret_t, args_t, Traits>::relay);

      jump_gen->push(to_uintptr(this));
      jump_gen->call(reinterpret_cast<void*>(&detail::save_ctx));
      jump_gen->add(esp, 4);
      jump_gen->jmp(relay);
    } else {
      const auto relay = reinterpret_cast<void*>(
        detail::unsafe_relay::relay_generator<hook, cconv, ret_t, args_t>::relay);

      jump_gen->pop(eax);
      jump_gen->mov(ptr[_storage0], eax);
#ifdef _WIN32
      if constexpr (cconv == traits::cconv::cthiscall) {
        jump_gen->push(ecx);
      }

      jump_gen->push(to_uintptr(this));

      if constexpr (cconv == traits::cconv::ccdecl) {
        jump_gen->call(relay);
        jump_gen->add(esp, 4);
        jump_gen->jmp(ptr[_storage0]);
      } else {
        jump_gen->push(eax);
        jump_gen->jmp(relay);
      }
#else
      static_assert(function::convention != detail::traits::cconv::cfastcall, "linux fastcall not supported");

      if constexpr (cconv == traits::cconv::cthiscall) {
        jump_gen->push(ecx);
      }

      jump_gen->push(to_uintptr(this));

      if constexpr (cconv == traits::cconv::ccdecl) {
        jump_gen->sub(esp, 12);
        jump_gen->call(relay);
        jump_gen->add(esp, 16);
        jump_gen->jmp(ptr[_storage0]);
      } else {
        if constexpr (cconv == traits::cconv::stdcall) {
          jump_gen->sub(esp, 12);
        }
        if constexpr (cconv == traits::cconv::thiscall) {
          jump_gen->sub(esp, 8);
        }
        jump_gen->push(eax);
        jump_gen->jmp(relay);
      }
#endif
    }
    utils::flush_instruction_cache(jump_gen->getCode(), jump_gen->getSize());
    return jump_gen->getCode();
  }

  kthook_error_code_t patch_hook(bool enable) {
    if (enable) {
      if (!this->relay_jump) {
        detail::hook_patch patch;

        this->relay_jump = static_cast<const std::uint8_t*>(generate_relay_jump());

        utils::frozen_threads threads;

        if constexpr (HookTraits::freeze_threads)
          if (!utils::freeze_threads(threads))
            return kthook_error_code_t::kThreadFreezeError;

        auto old_prot = utils::get_memory_prot(reinterpret_cast<void*>(info.hook_address));
        if (!utils::set_memory_prot(info.hook_address_ptr, this->hook_size, utils::MemoryProt::PROTECT_RWE))
          return kthook_error_code_t::kMemoryProtectionFailure;

        info.original_code = std::make_unique<std::uint8_t[]>(this->hook_size);
        std::memcpy(info.original_code.get(), info.hook_address_ptr, this->hook_size);

        uintptr_t relative =
            utils::get_relative_address(reinterpret_cast<std::uintptr_t>(this->relay_jump), info.hook_address);
        std::memcpy(&patch, info.hook_address_ptr, sizeof(patch));
        if (patch.opcode != 0xE8) {
          patch.opcode = 0xE9;
        }

        patch.operand = relative;
        std::memcpy(info.hook_address_ptr, &patch, sizeof(patch));

        std::memset(reinterpret_cast<void*>(info.hook_address + sizeof(patch)), 0x90,
                    this->hook_size - sizeof(patch));

        if (!utils::set_memory_prot(info.hook_address_ptr, this->hook_size, old_prot))
          return kthook_error_code_t::kMemoryProtectionFailure;

        if constexpr (HookTraits::freeze_threads)
          if (!utils::unfreeze_threads(threads))
            return kthook_error_code_t::kThreadFreezeError;
      } else {
        jump_gen->rewrite(0, original, 8);
      }
    } else if (relay_jump) {
      std::memcpy(&original, relay_jump, sizeof(original));
      jump_gen->rewrite(0, 0x9090909090909090, 8);
    }
    utils::flush_instruction_cache(relay_jump, jump_gen->getSize());
    return kthook_error_code_t::kOk;
  }

  detail::hook_info info;
  std::size_t hook_size{0};
  std::uint64_t original{0};
  std::unique_ptr<Xbyak::CodeGenerator> jump_gen{get_jmp_generator()};
  std::unique_ptr<Xbyak::CodeGenerator> trampoline_gen{std::make_unique<Xbyak::CodeGenerator>()};

  const std::uint8_t* relay_jump{nullptr};

public:
  detail::ctx_storage<HookTraits> ctx_storage;

private:
  bool installed = false;
};
}

#endif // KTHOOK_IMPL_HPP_
