#ifndef KTHOOK_TRAITS_SIGNATURE_HPP_
#define KTHOOK_TRAITS_SIGNATURE_HPP_

namespace kthook::traits {
template <typename T, typename F>
struct signature {
  using type = typename T::range;

  signature(F f)
    : f(std::move(f)) {
  }

  F f;
};
}

template <std::size_t... Is, typename F, typename =
          std::enable_if_t<kthook::traits::is_callable_v<F>>>
constexpr kthook::traits::signature<kthook::traits::range<Is...>, F> operator+(kthook::traits::range<Is...>, F f) {
  return kthook::traits::signature<kthook::traits::range<Is...>, F>{std::move(f)};
}

#endif // KTHOOK_TRAITS_SIGNATURE_HPP_