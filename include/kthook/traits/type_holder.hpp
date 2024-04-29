#ifndef KTHOOK_TRAITS_TYPE_HOLDER_HPP_
#define KTHOOK_TRAITS_TYPE_HOLDER_HPP_

namespace kthook::traits {
template <typename... Ts>
struct type_holder {
  static constexpr auto size = sizeof...(Ts);
};

template <typename... Ts, typename... Us>
type_holder<Ts..., Us...> operator+(type_holder<Ts...>, type_holder<Us...>) {
  return type_holder<Ts..., Us...>{};
}

template <typename... TypeHolders>
struct type_holder_concat {
  using type = decltype((TypeHolders{} + ... + type_holder<>{}));
};

template <typename... TypeHolders>
using type_holder_concat_t = typename type_holder_concat<TypeHolders...>::type;
}

#endif // KTHOOK_TRAITS_TYPE_HOLDER_HPP_