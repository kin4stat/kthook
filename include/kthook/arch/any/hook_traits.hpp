#ifndef KTHOOK_ARCH_ANY_HOOK_TRAITS_HPP_
#define KTHOOK_ARCH_ANY_HOOK_TRAITS_HPP_
namespace kthook {
/**
 * Base template for any hook on any arch
 *
 * Can be used for customizing hook behaviour
 * @tparam FuncSig Signature of function
 */
template <typename FuncSig>
struct hook_any_traits_template {
  /**
   * @brief if true, then all threads will be suspended before injection of the hook
   */
  static constexpr auto freeze_threads = false;
  ///**
  // * @brief if true, then all contexts, that you can access from @p hook_interface would be mutable
  // */
  //static constexpr auto mutable_context = false;
  /**
   * @brief if true, then you can call hooked function inside hook
   */
  static constexpr auto allow_recursive_calls = true;

  /**
   * @brief if true, then kthook uses thread local variable to get context inside hook callback
   *
   * Disable if TLS isn't available in your environment
   *
   * @note disabling this activates `unsafe` mode, so your code with kthook may crash
   */
  static constexpr auto use_thread_locals = true;


  using function = arch::function_traits<FuncSig>;

  /**
   * @brief arguments of the hook
   */
  using hook_args_t = typename function::args;

  /**
   * @brief return type of the hook
   */
  using hook_ret_t = typename function::return_type;
};
}
#endif // KTHOOK_ARCH_ANY_HOOK_TRAITS_HPP_