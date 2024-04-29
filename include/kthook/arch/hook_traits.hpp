#ifndef KTHOOK_ARCH_HOOK_TRAITS_HPP_
#define KTHOOK_ARCH_HOOK_TRAITS_HPP_

#if defined(KTHOOK_32)
#include "any/hook_traits.hpp"
#include "x86/hook_traits.hpp"
#elif

#endif

namespace kthook {
template <typename FuncSig>
struct hook_traits : hook_traits_template<FuncSig> {
  using _base = hook_traits_template<FuncSig>;

  using _hook = hook<FuncSig, hook_traits>;
  using _hook_interface = hook_interface<FuncSig, hook_traits>;

  using callback_args_t = traits::type_holder_concat_t<traits::type_holder<_hook*>, typename _base::hook_args_t>;
  using callback_signature_t = arch::function_connect_t<typename _base::hook_ret_t, callback_args_t>;

  using user_callback_args_t = traits::type_holder_concat_t<
    traits::type_holder<_hook_interface&>, typename _base::hook_args_t>;
  using user_callback_signature_t = arch::function_connect_t<typename _base::hook_ret_t, user_callback_args_t>;

  std::function<callback_signature_t> callback;

  decltype(callback)& get_callback() {
    return callback;
  }

  void set_callback(std::function<user_callback_signature_t> cb) {
    callback = [callback = std::move(cb)]<typename... Ts>(_hook* this_hook, Ts&&... args) {
      auto interface_ = hook_interface<FuncSig, hook_traits>::create(
          this_hook,
          this_hook->ctx_storage_stack.top(),
          traits::discarded_holder<void>{});

      return callback(interface_, std::forward<Ts...>(args)...);
    };
  }

  template <typename T>
  void set_callback_wrapped(T f) {
    callback = [func = std::move(f)]<typename... Ts>(_hook* this_hook, Ts&&... args) {
      auto d = traits::discarded_impl<std::tuple<Ts...>>{
          [&]<std::size_t... Is>(traits::range<Is...>) {
            return std::tuple<Ts...>{std::forward<Ts>(args)...};
          }(traits::invert_range<typename T::type, _base::hook_args_t::size>{})
      };

      auto interface_ = hook_interface<FuncSig, hook_traits, discarded, typename T::type>::create(
          this_hook,
          this_hook->ctx_storage_stack.top(),
          {static_cast<discarded&>(d)}
          );
      return [&]<std::size_t... Is>(traits::range<Is...>) {
        auto tuple = std::forward_as_tuple<Ts...>(std::forward<Ts>(args)...);
        return func.f(interface_, traits::perfect_get<Is>(tuple)...);
      }(typename T::type{});
    };
  }
};
}
#endif // KTHOOK_ARCH_HOOK_TRAITS_HPP_