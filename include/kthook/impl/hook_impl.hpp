#ifndef KTHOOK_HOOK_IMPL_HPP_
#define KTHOOK_HOOK_IMPL_HPP_

namespace kthook {
template <typename FuncSig, template<typename, typename> typename Impl, template<typename> typename Traits>
class hook
    : public Impl<FuncSig, Traits<FuncSig>>,
      public Traits<FuncSig> {
public:
  using HookImpl = Impl<FuncSig, Traits<FuncSig>>;
  using HookTraits = Traits<FuncSig>;
  using FunctionSignature = FuncSig;

  /**
   * Default constructor, initializes hook to nullptr
   */
  hook() : HookImpl(typename HookImpl::default_args{}) {
  }

  /**
   * 
   * @param destination address where to set hook
   * @param force_enable enable hook right after construction
   */
  hook(typename HookImpl::args args, bool force_enable) : HookImpl(std::move(args)) {
    if (force_enable) {
      HookImpl::template install<hook>();
    }
  }

  ~hook() {
    HookImpl::remove();
  }

  /**
   * Installs the hook(won't install if destination address is not executable page)
   * @return error, if occurred
   */
  error_code_t install() {
    return HookImpl::template install<hook>();
  }

  /**
   * Removes the hook, but keeps trampoline, so if there any other hooks, process won't crash
   * @return error, if occurred
   */
  error_code_t remove() {
    return HookImpl::remove();
  }

  /**
   * Removes the hook completely, returning the instructions that were there before
   * @return error, if occurred
   */
  error_code_t reset() {
    return HookImpl::reset();
  }

  /**
   * Sets the new hook address.
   *
   * If the hook was installed before, it calls @p reset, and then @p install with a new address
   * @param address new hook address
   */
  error_code_t set_dest(typename HookImpl::set_dest_args args) {
    return HookImpl::set_dest(std::move(args));
  }
  /**
   * 
   * @return boolean was the hook installed before
   */
  bool is_installed() const noexcept {
    return HookImpl::is_installed();
  }
};

template<typename FuncSig, template<typename> typename Traits = hook_traits>
using hook_safe = hook<FuncSig, win_x86_32_inline_impl_safe, Traits>;

template<typename FuncSig, template<typename> typename Traits = hook_traits>
using hook_unsafe = hook<FuncSig, win_x86_32_inline_impl_unsafe, Traits>;
}

#endif // KTHOOK_HOOK_IMPL_HPP_