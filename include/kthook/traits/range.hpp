#ifndef KTHOOK_TRAITS_RANGE_HPP_
#define KTHOOK_TRAITS_RANGE_HPP_

namespace kthook::traits {
template <std::size_t... Is>
struct range {
  using value = std::index_sequence<Is...>;
};

template <std::size_t N, std::size_t... Seq>
constexpr range<N + Seq...> add(std::index_sequence<Seq...>) { return {}; }

template <std::size_t Min, std::size_t Max>
using make_index_range = decltype(add<Min>(std::make_index_sequence<Max - Min>{}));

template <std::size_t... Is, std::size_t... Us>
constexpr range<Is..., Us...> operator+(range<Is...>, range<Us...>) {
  return {};
}

template <std::size_t... Is, std::size_t... Us>
constexpr auto invert_range_impl(range<Is...>, range<Us...>) {
  return (range{} + ... + make_index_range<Is + 1, Us>{});
}

template <typename Range, std::size_t N>
using invert_range = decltype(invert_range_impl(range<static_cast<std::size_t>(-1)>{} + Range{},
                                                Range{} + range<N>{})
);
}

#endif // KTHOOK_TRAITS_RANGE_HPP_