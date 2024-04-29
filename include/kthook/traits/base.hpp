#ifndef KTHOOK_TRAITS_BASE_HPP_
#define KTHOOK_TRAITS_BASE_HPP_

namespace kthook::traits {
template <bool, typename T>
struct is_callable_impl : std::is_function<std::remove_pointer_t<std::remove_reference_t<T>>> {
};

template <typename T>
struct is_callable_impl<true, T> {
private:
  struct Fallback {
    // ReSharper disable once CppFunctionIsNotImplemented
    void operator()();
  };

  struct Derived : T, Fallback {
  };

  template <typename U, U>
  struct Check;

  template <typename>
  // ReSharper disable once CppFunctionIsNotImplemented
  static std::true_type test(...);

  template <typename C>
  // ReSharper disable once CppFunctionIsNotImplemented
  static std::false_type test(Check<void (Fallback::*)(), &C::operator()>*);

public:
  static constexpr auto value = decltype(test<Derived>(nullptr))::value;
};

template <typename T>
constexpr auto is_callable_v = is_callable_impl<std::is_class_v<std::remove_reference_t<T>>,
                                                std::remove_reference_t<T>>::value;

template <std::size_t I, class... Types>
constexpr std::enable_if_t<
  !std::is_rvalue_reference_v<std::tuple_element_t<I, std::tuple<Types...>>>,
  std::tuple_element_t<I, std::tuple<Types...>>&>
perfect_get(std::tuple<Types...>& t) noexcept {
  return std::get<I>(t);
}

// If the element is an rvalue reference, move the result of std::get
template <std::size_t I, class... Types>
constexpr std::enable_if_t<
  std::is_rvalue_reference_v<std::tuple_element_t<I, std::tuple<Types...>>>,
  std::tuple_element_t<I, std::tuple<Types...>>
>
perfect_get(std::tuple<Types...>& t) noexcept {
  return std::move(std::get<I>(t));
}
}

#endif // KTHOOK_TRAITS_BASE_HPP_