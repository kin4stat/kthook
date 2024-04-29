#ifndef KTHOOK_X86_64_HOOK_TRAITS_HPP_
#define KTHOOK_X86_64_HOOK_TRAITS_HPP_

namespace kthook {
namespace utils {
template <typename FuncSig>
struct hook_traits_template {
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


  using function = traits::function_traits<FuncSig>;

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

template <typename FuncSig>
struct hook_traits : utils::hook_traits_template<FuncSig> {
  using _base = utils::hook_traits_template<FuncSig>;

  /*using hook_traits::function;
  using hook_traits::hook_args_t;
  using hook_traits::hook_ret_t;
  using hook_traits::trampoline_signature_t;

  using hook_traits::save_x87;
  using hook_traits::save_flags;
  using hook_traits::save_regs;
  using hook_traits::save_segment_regs;
  using hook_traits::freeze_threads;
  using hook_traits::mutable_context;
  
  using hook_traits::allow_recursive_calls;*/

  using _hook = hook<FuncSig, hook_traits>;
  using _hook_interface = hook_interface<FuncSig, hook_traits>;

  using callback_args_t = traits::type_holder_concat_t<traits::type_holder<_hook*>, typename _base::hook_args_t>;
  using callback_signature_t = traits::function_connect_t<typename _base::hook_ret_t, callback_args_t>;

  using user_callback_args_t = traits::type_holder_concat_t<
    traits::type_holder<_hook_interface&>, typename _base::hook_args_t>;
  using user_callback_signature_t = traits::function_connect_t<typename _base::hook_ret_t, user_callback_args_t>;

  std::function<callback_signature_t> callback;

  decltype(callback)& get_callback() {
    return callback;
  }

  void set_callback(std::function<user_callback_signature_t> cb) {
    callback = [callback = std::move(cb)]<typename... Ts>(_hook* this_hook, Ts&&... args) {
      auto interface_ = hook_interface<FuncSig, hook_traits>::create(
          this_hook,
          this_hook->ctx_storage_stack.top(),
          detail::discarded_holder<void>{});

      return callback(interface_, std::forward<Ts...>(args)...);
    };
  }

  template <typename T>
  void set_callback_wrapped(T f) {
    callback = [func = std::move(f)]<typename... Ts>(_hook* this_hook, Ts&&... args) {
      auto d = detail::discarded_impl<std::tuple<Ts...>>{
          [&]<std::size_t... Is>(range<Is...>) {
            return std::tuple<Ts...>{std::forward<Ts>(args)...};
          }(detail::invert_range<typename T::type, _base::hook_args_t::size>{})
      };

      auto interface_ = hook_interface<FuncSig, hook_traits, discarded, typename T::type>::create(
          this_hook,
          this_hook->ctx_storage_stack.top(),
          { static_cast<discarded&>(d) }
          );
      return [&]<std::size_t... Is>(range<Is...>) {
        auto tuple = std::forward_as_tuple<Ts...>(std::forward<Ts>(args)...);
        return func.f(interface_, traits::perfect_get<Is>(tuple)...);
      }(typename T::type{});
    };
  }
};
} // namespace kthook

#endif // #ifndef KTHOOK_X86_64_TRAITS_HPP_
