#ifndef KTHOOK_INLINE_X86_32_IMPL_UNSAFE_HPP_
#define KTHOOK_INLINE_X86_32_IMPL_UNSAFE_HPP_

namespace kthook {
template <typename FuncSig, template<typename> typename Traits>
struct win_x86_32_inline_impl_safe : public win_x86_32_inline_impl_base<
      FuncSig, Traits, win_x86_32_inline_impl_safe<FuncSig, Traits>> {
protected:
  using HookTraits = Traits<FuncSig>;

  using base = win_x86_32_inline_impl_base<FuncSig, Traits, win_x86_32_inline_impl_safe>;

  using default_args = typename base::default_args;
  using args = typename base::args;
  using set_dest_args = typename base::set_dest_args;

  win_x86_32_inline_impl_safe(default_args args) : base(args) {
  }

  win_x86_32_inline_impl_safe(args args) : base(args) {
  }

  win_x86_32_inline_impl_safe(const win_x86_32_inline_impl_safe& other) = delete;
  win_x86_32_inline_impl_safe(win_x86_32_inline_impl_safe&& other) noexcept = default;
  win_x86_32_inline_impl_safe& operator=(const win_x86_32_inline_impl_safe& other) = delete;
  win_x86_32_inline_impl_safe& operator=(win_x86_32_inline_impl_safe&& other) noexcept = default;

  ~win_x86_32_inline_impl_safe() = default;

protected:
  /**
   * Generates asm for saving context and forwarding hook interface to callback
   * @return pointer to generated relay between hook and original function
   */
  template <typename Hook>
  void generate_relay_jump_impl() {
    using namespace Xbyak::util;

    std::unique_ptr<Xbyak::CodeGenerator>& generator = this->jump_gen;

    constexpr auto cconv = HookTraits::function::convention;
    using ret_t = typename HookTraits::hook_ret_t;
    using args_t = typename HookTraits::hook_args_t;
    const auto relay = reinterpret_cast<void*>(
      arch::unsafe_relay::relay_generator<Hook, cconv, ret_t, args_t>::relay);

    auto to_uintptr = [](auto v) -> std::uintptr_t {
      return reinterpret_cast<std::uintptr_t>(v);
    };

    std::uintptr_t _storage0 = to_uintptr(utils::get_frame_ctx_storage(this));

    generator->pop(eax);
    generator->mov(ptr[_storage0], eax);
#ifdef _WIN32
    if constexpr (cconv == arch::cconv::cthiscall) {
      generator->push(ecx);
    }

    generator->push(to_uintptr(this));

    if constexpr (cconv == arch::cconv::ccdecl) {
      generator->call(relay);
      generator->add(esp, 4);
      generator->jmp(ptr[_storage0]);
    } else {
      generator->push(eax);
      generator->jmp(relay);
    }
#else
    static_assert(function::convention != detail::traits::cconv::cfastcall, "linux fastcall not supported");

    if constexpr (cconv == traits::cconv::cthiscall) {
      generator->push(ecx);
    }

    generator->push(to_uintptr(this));

    if constexpr (cconv == traits::cconv::ccdecl) {
      generator->sub(esp, 12);
      generator->call(relay);
      generator->add(esp, 16);
      generator->jmp(ptr[_storage0]);
    } else {
      if constexpr (cconv == traits::cconv::stdcall) {
        generator->sub(esp, 12);
      }
      if constexpr (cconv == traits::cconv::thiscall) {
        generator->sub(esp, 8);
      }
      generator->push(eax);
      generator->jmp(relay);
    }
#endif
  }
};
}

#endif // KTHOOK_INLINE_X86_32_IMPL_UNSAFE_HPP_