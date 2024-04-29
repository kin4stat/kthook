#ifndef KTHOOK_ARGS_PACK_HPP_
#define KTHOOK_ARGS_PACK_HPP_

namespace kthook::detail {
template <std::size_t N, std::size_t... Seq>
constexpr range<N + Seq...> add(std::index_sequence<Seq...>) { return {}; }

template <std::size_t Min, std::size_t Max>
using make_index_range = decltype(add<Min>(std::make_index_sequence<Max - Min>()));
}

namespace kthook {
/**
 * @brief
 * Used to indicate that function takes args only in range @p Start - @p End
 *
 * Ranges can be combined via operator+
 *
 * Example usage:
 * @code
 * using callback_type = void(int, float, double, char, short, long);
 *
 * void myfunction(discarded& d, float, short, long);
 * void foo(callback_type);
 *
 * foo(keep<1> + keep<4, 5> + &myfunction); // ok
 * @endcode
 * @tparam Start Start of range 
 * @tparam End End of range
 */
template <std::size_t Start, std::size_t End = Start + 1>
constexpr auto keep = detail::make_index_range<Start, End>{};
}

namespace kthook::detail {
template <typename Tuple>
struct discarded_impl : discarded {
  Tuple value;

  explicit discarded_impl(Tuple value)
    : value(std::move(value)) {
  }
};

template <typename T, typename F>
struct signature {
  using type = typename T::range;

  signature(F f)
    : f(std::move(f)) {
  }

  F f;
};

template <std::size_t... Is, std::size_t... Us>
constexpr auto invert_range_impl(range<Is...>, range<Us...>) {
  return (make_index_range<Is + 1, Us>{} + ... + range{});
}

template <typename Range, std::size_t N>
using invert_range = decltype(invert_range_impl(range<static_cast<std::size_t>(-1)>{} + Range{},
                                                Range{} + range<N>{})
);


}

template <std::size_t... Is, std::size_t... Us>
constexpr kthook::range<Is..., Us...> operator+(kthook::range<Is...>, kthook::range<Us...>) {
  return {};
}

template <std::size_t... Is, typename F, typename =
          std::enable_if_t<kthook::traits::is_callable_v<F>>>
constexpr kthook::detail::signature<kthook::range<Is...>, F> operator+(kthook::range<Is...>, F f) {
  return kthook::detail::signature<kthook::range<Is...>, F>{std::move(f)};
}
#endif // #ifdef KTHOOK_ARGS_PACK_HPP_
