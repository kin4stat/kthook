#ifndef KTHOOK_TRAITS_HPP_
#define KTHOOK_TRAITS_HPP_

namespace kthook::traits {
enum class cconv {
  ccdecl,
  cfastcall,
  cthiscall,
  cstdcall,
  cvectorcall,
};

template <cconv Conv, typename Ret, typename TypeHolder>
struct function_connect_ptr;

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::ccdecl, Ret, type_holder<Args...>> {
  using type = Ret(CCDECL*)(Args...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cstdcall, Ret, type_holder<Args...>> {
  using type = Ret(CSTDCALL*)(Args...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cthiscall, Ret, type_holder<Args...>> {
  using type = Ret(CTHISCALL*)(Args...);
};

template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cfastcall, Ret, type_holder<Args...>> {
  using type = Ret(CFASTCALL*)(Args...);
};

#ifdef _MSC_VER
template <typename Ret, typename... Args>
struct function_connect_ptr<cconv::cvectorcall, Ret, type_holder<Args...>> {
  using type = Ret(CVECTORCALL*)(Args...);
};
#endif

template <class R, class TypeHolder>
struct function_connect;

template <class R, class... Types>
struct function_connect<R, type_holder<Types...>> {
  using type = R(Types...);
};

template <typename Pointer>
struct function_traits;

template <typename Ret, typename Class, typename... Args>
struct function_traits<Ret (Class::*)(Args...)> {
  static constexpr auto args_count = sizeof...(Args) + 1;
#ifdef _WIN32
  static constexpr auto convention = cconv::cthiscall;
#else
  static constexpr auto convention = cconv::ccdecl;
#endif
  using args = type_holder<Class*, Args...>;
  using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CCDECL *)(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::ccdecl;
  using args = type_holder<Args...>;
  using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::cstdcall;
  using args = type_holder<Args...>;
  using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CTHISCALL *)(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::cthiscall;
  using args = type_holder<Args...>;
  using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CSTDCALL *)(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::cstdcall;
  using args = type_holder<Args...>;
  using return_type = Ret;
};

template <typename Ret, typename... Args>
struct function_traits<Ret(CFASTCALL *)(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::cfastcall;
  using args = type_holder<Args...>;
  using return_type = Ret;
};

#ifdef _MSC_VER
template <typename Ret, typename... Args>
struct function_traits<Ret(CVECTORCALL *)(Args...)> {
  static constexpr auto args_count = sizeof...(Args);
  static constexpr auto convention = cconv::cvectorcall;
  using args = type_holder<Args...>;
  using return_type = Ret;
};
#endif

template <cconv Conv, typename Ret, typename... Args>
using function_connect_ptr_t = typename function_connect_ptr<Conv, Ret, Args...>::type;

template <class R, class Types>
using function_connect_t = typename function_connect<R, Types>::type;
} // namespace kthook::traits

#endif // KTHOOK_TRAITS_HPP_