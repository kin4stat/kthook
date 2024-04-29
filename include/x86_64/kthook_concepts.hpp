#ifndef KTHOOK_CONCEPTS_HPP_
#define KTHOOK_CONCEPTS_HPP_

namespace kthook {
template <typename Interface, typename Traits>
concept has_int_regs_ctx = !Traits::save_regs || requires(Interface v) {
  { v.int_regs() } -> std::same_as<const cpu_ctx_int&>;
};
template <typename Interface, typename Traits>
concept has_fpu_ctx = !Traits::save_x87 || requires(Interface v) {
  { v.fpu_state() } -> std::same_as<const cpu_ctx_x87&>;
};

template <typename Interface, typename Traits>
concept has_segment_regs_ctx = !Traits::save_segment_regs || requires(Interface v) {
  { v.segment_regs() } -> std::same_as<const cpu_ctx_segment_regs&>;
};

template <typename Interface, typename Traits>
concept has_flags_ctx = !Traits::save_flags || requires(Interface v) {
  { v.cpu_flags() } -> std::same_as<const cpu_ctx_flags&>;
};

template <typename T, template<typename> typename Traits = hook_traits>
concept interface = requires(T v) {
                      { v.return_address() } -> std::same_as<std::uintptr_t>;
                      { v.install() } -> std::same_as<kthook_error_code_t>;
                      { v.remove() } -> std::same_as<kthook_error_code_t>;
                    } &&
                    has_int_regs_ctx<T, typename T::HookTraits> &&
                    has_fpu_ctx<T, typename T::HookTraits> &&
                    has_segment_regs_ctx<T, typename T::HookTraits> &&
                    has_flags_ctx<T, typename T::HookTraits>;
}
#endif // #ifndef KTHOOK_CONCEPTS_HPP_
