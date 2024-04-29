#ifndef KTHOOK_ARCH_X32_HOOK_TRAITS_HPP_
#define KTHOOK_ARCH_X32_HOOK_TRAITS_HPP_

namespace kthook {
/**
 * Base template for any hook on x86 arch
 *
 * Can be used for customizing hook behaviour
 * @tparam FuncSig Signature of function
 */
template <typename FuncSig>
struct hook_x86_traits_template : public hook_any_traits_template<FuncSig> {
  /**
   * @brief if true, then x87 fpu state are saved before calling callback
   * could be accessed using method #hook_interface::cpu_x87
   */
  static constexpr auto save_x87 = true;
  /**
   * @brief if true, then CPU EFLAGS are saved before calling callback
   * could be accessed using method #hook_interface::cpu_flags
   */
  static constexpr auto save_flags = false;
  /**
   * @brief if true, then CPU integer registers are saved before calling callback
   * could be accessed using method #hook_interface::cpu_ctx
   */
  static constexpr auto save_regs = false;
  /**
   * @brief if true, then CPU segments registers are saved before calling callback
   * could be accessed using method #hook_interface::cpu_segment_regs
   */
  static constexpr auto save_segment_regs = false;
};


template <typename FuncSig>
using hook_traits_template = hook_x86_traits_template<FuncSig>;
}
#endif // KTHOOK_ARCH_X32_HOOK_TRAITS_HPP_