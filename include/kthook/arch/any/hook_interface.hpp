#ifndef KTHOOK_ARCH_ANY_HOOK_INTERFACE_HPP_
#define KTHOOK_ARCH_ANY_HOOK_INTERFACE_HPP_

namespace kthook {
/**
 * Interface, that will be forwarded to hook callback.
 *
 * @note See @p kthook::interface concept for additional info
 * @tparam FuncSig Signature of hook
 * @tparam Traits Traits of hook
 * @tparam Discarded Values that have been discarded using @p kthook::keep
 * @tparam Range Values that have been kept using @p kthook::keep and will be forwarded to callback
 */
template <typename FuncSig, template<typename U> typename Traits, typename Discarded, typename Range>
struct hook_interface
    : arch::detail::ctx_storage<Traits<FuncSig>> {
  using HookTraits = Traits<FuncSig>;
  using FunctionSignature = FuncSig;

  hook_interface(hook<FuncSig, Traits>* this_hook,
                 arch::detail::ctx_storage<Traits<FuncSig>>& storage,
                 traits::discarded_holder<Discarded> d)
    : arch::detail::ctx_storage<Traits<FuncSig>>(storage),
      this_hook(this_hook),
      d(d) {
  }

  /**
   * Fabric method for creating hook_interface
   * @param this_hook pointer to hook, for this instance
   * @param ctx_storage reference to cpu context storage
   * @param d discarded values temporary storage
   * @return new instance of hook_interface
   */
  static hook_interface create(hook<FuncSig, Traits>* this_hook,
                               arch::detail::ctx_storage<HookTraits>& ctx_storage,
                               traits::discarded_holder<Discarded> d) {
    return hook_interface{this_hook, ctx_storage, d};
  }

  /**
   * 
   * @return return address of hook
   */
  std::uintptr_t return_address() const noexcept {
    return this->last_return_address;
  }

  /**
   * Method for installing hook inside hook callback
   *
   * Effectively, calls @p kthook::hook::install()
   * @return error, if occurred
   */
  error_code_t install();
  /**
   * Method for disabling hook inside hook callback
   *
   * Effectively, calls @p kthook::hook::remove()
   * @return error, if occurred
   */
  error_code_t remove();

  /**
   * Calls the original function, using all arguments
   * @return return value of hooked function
   */
  typename HookTraits::hook_ret_t call_trampoline();

  hook<FuncSig, Traits>* this_hook;
  traits::discarded_holder<Discarded> d;
  using range = Range;
};
} // namespace kthook

#endif // KTHOOK_ARCH_ANY_HOOK_INTERFACE_HPP_