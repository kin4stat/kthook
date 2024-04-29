#ifndef KTHOOK_X86_64_TRAITS_HPP_
#define KTHOOK_X86_64_TRAITS_HPP_

namespace kthook::traits {
template <typename... Ts>
struct type_holder {
  static constexpr auto size = sizeof...(Ts);
};

template <typename... Ts, typename... Us>
type_holder<Ts..., Us...> operator+(type_holder<Ts...>, type_holder<Us...>) {
  return type_holder<Ts..., Us...>{};
}

template <bool has_value, typename T>
struct hold_type_if {
  using type = type_holder<T>;
};

template <typename T>
struct hold_type_if<false, T> {
  using type = type_holder<>;
};

template <bool has_value, typename T>
using hold_type_if_t = typename hold_type_if<has_value, T>::type;

template <typename... TypeHolders>
struct type_holder_concat {
  using type = decltype((TypeHolders{} + ... + type_holder<>{}));
};

template <typename... TypeHolders>
using type_holder_concat_t = typename type_holder_concat<TypeHolders...>::type;

template <typename TypeHolder, template <typename> typename T>
struct type_holder_as {
};

template <typename... Ts, template <typename...> typename T>
struct type_holder_as<type_holder<Ts...>, T> {
  using type = T<Ts...>;
};

template <typename TypeHolder, template <typename...> typename T>
using type_holder_as_t = typename type_holder_as<TypeHolder, T>::type;

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
} // namespace kthook::traits
#endif // #ifndef KTHOOK_X86_64_TRAITS_HPP_
