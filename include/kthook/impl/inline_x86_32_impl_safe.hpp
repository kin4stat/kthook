#ifndef KTHOOK_INLINE_X86_32_IMPL_SAFE_HPP_
#define KTHOOK_INLINE_X86_32_IMPL_SAFE_HPP_

namespace kthook {
template <typename FuncSig, template<typename> typename Traits>
struct win_x86_32_inline_impl_unsafe : public win_x86_32_inline_impl_base<
      FuncSig, Traits, win_x86_32_inline_impl_unsafe<FuncSig, Traits>> {
protected:
  using HookTraits = Traits<FuncSig>;

  using base = win_x86_32_inline_impl_base<FuncSig, Traits, win_x86_32_inline_impl_unsafe>;

  using default_args = typename base::default_args;
  using args = typename base::args;
  using set_dest_args = typename base::set_dest_args;

  win_x86_32_inline_impl_unsafe(default_args args) : base(args) {
  }

  win_x86_32_inline_impl_unsafe(args args) : base(args) {
  }

  win_x86_32_inline_impl_unsafe(const win_x86_32_inline_impl_unsafe& other) = delete;
  win_x86_32_inline_impl_unsafe(win_x86_32_inline_impl_unsafe&& other) noexcept = default;
  win_x86_32_inline_impl_unsafe& operator=(const win_x86_32_inline_impl_unsafe& other) = delete;
  win_x86_32_inline_impl_unsafe& operator=(win_x86_32_inline_impl_unsafe&& other) noexcept = default;

  ~win_x86_32_inline_impl_unsafe() = default;

protected:
  /**
   * Generates asm for saving context and forwarding hook interface to callback
   * @return pointer to generated relay between hook and original function
   */
  template<typename Hook>
  void generate_relay_jump_impl() {
    using namespace Xbyak::util;

    constexpr auto cconv = HookTraits::function::convention;
    using ret_t = typename HookTraits::hook_ret_t;
    using args_t = typename HookTraits::hook_args_t;

    const auto relay = reinterpret_cast<void*>(
      arch::safe_relay::relay_generator<Hook, cconv, ret_t, args_t, Traits>::relay);

    auto to_uintptr = [](auto v) -> std::uintptr_t {
      return reinterpret_cast<std::uintptr_t>(v);
    };

    this->jump_gen->push(to_uintptr(this));
    this->jump_gen->call(reinterpret_cast<void*>(utils::save_ctx));
    this->jump_gen->add(esp, 4);
    this->jump_gen->jmp(relay);
  }
};
}

#endif // KTHOOK_INLINE_X86_32_IMPL_SAFE_HPP_