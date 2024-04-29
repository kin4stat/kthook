#ifndef KTHOOK_TRAITS_DISCARDED_VALUES_HPP_
#define KTHOOK_TRAITS_DISCARDED_VALUES_HPP_

namespace kthook::traits {
/**
 * Used for holding discarded values using @p kthook::keep
 * @tparam T Type of value
 */
template <typename T>
struct discarded_holder {
  T& value;
};

template <>
struct discarded_holder<void> {
};

template <typename Tuple>
struct discarded_impl : discarded {
  Tuple value;

  explicit discarded_impl(Tuple value)
    : value(std::move(value)) {
  }
};
}

#endif // KTHOOK_TRAITS_DISCARDED_VALUES_HPP_