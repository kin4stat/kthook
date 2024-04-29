#ifndef KTHOOK_RELAY_GENERATORS_HPP_
#define KTHOOK_RELAY_GENERATORS_HPP_

#define KTHOOK_DECLARE_RELAY_BODY \
  HookPtrType* this_hook = utils::get_ctx<HookPtrType>();                                 \
                                                                                          \
  if constexpr (HookTraits::allow_recursive_calls) {                                      \
    this_hook->ctx_storage_stack.emplace(std::move(this_hook->ctx_storage));              \
  }                                                                                       \
                                                                                          \
  auto& cb = this_hook->get_callback();                                                   \
                                                                                          \
  if constexpr (HookTraits::allow_recursive_calls) {                                      \
    utils::scope_exit guard{                                                              \
        [&]() {                                                                           \
          this_hook->ctx_storage = std::move(this_hook->ctx_storage_stack.top());         \
          this_hook->ctx_storage_stack.pop();                                             \
        }                                                                                 \
    };                                                                                    \
                                                                                          \
    return common_relay<decltype(cb), HookPtrType, Traits, Ret, Args...>(cb, this_hook, args...); \
  } else {                                                                                \
    return common_relay<decltype(cb), HookPtrType, Traits, Ret, Args...>(cb, this_hook, args...); \
  }

namespace kthook::arch {
template <typename CallbackT, typename HookPtrType, template<typename> typename Traits, typename Ret, typename... Args>
inline Ret common_relay(CallbackT& cb, HookPtrType* this_hook, Args&... args) {
  return cb(this_hook, args...);
}
}

namespace kthook::arch::safe_relay {
template <typename HookPtrType, cconv Convention, typename Ret, typename Tuple, template<typename> typename
          Traits>
struct relay_generator;

template <typename HookPtrType, typename Ret, typename... Args, template<typename> typename Traits>
struct relay_generator<HookPtrType, cconv::ccdecl, Ret, traits::type_holder<Args...>, Traits> {
  using HookTraits = typename HookPtrType::HookTraits;

  static Ret CCDECL relay(Args... args) {
    KTHOOK_DECLARE_RELAY_BODY
  }
};

template <typename HookPtrType, typename Ret, typename... Args, template<typename> typename Traits>
struct relay_generator<HookPtrType, cconv::cstdcall, Ret, traits::type_holder<Args...>, Traits> {
  using HookTraits = typename HookPtrType::HookTraits;

  static Ret CSTDCALL relay(Args... args) {
    KTHOOK_DECLARE_RELAY_BODY
  }
};

template <typename HookPtrType, typename Ret, typename... Args, template<typename> typename Traits>
struct relay_generator<HookPtrType, cconv::cthiscall, Ret, traits::type_holder<Args...>, Traits> {
  using HookTraits = typename HookPtrType::HookTraits;

  static Ret CSTDCALL relay(Args... args) {
    KTHOOK_DECLARE_RELAY_BODY
  }
};

template <typename HookPtrType, typename Ret, typename... Args, template<typename> typename Traits>
struct relay_generator<HookPtrType, cconv::cfastcall, Ret, traits::type_holder<Args...>, Traits> {
  using HookTraits = typename HookPtrType::HookTraits;

  static Ret CFASTCALL relay(Args... args) {
    KTHOOK_DECLARE_RELAY_BODY
  }
};

#ifdef _MSC_VER
template <typename HookPtrType, typename Ret, typename... Args, template<typename> typename Traits>
struct relay_generator<HookPtrType, cconv::cvectorcall, Ret, traits::type_holder<Args...>, Traits> {
  using HookTraits = typename HookPtrType::HookTraits;

  static Ret CVECTORCALL relay(Args... args) {
    KTHOOK_DECLARE_RELAY_BODY
  }
};
#endif // #ifdef _MSC_VER
}

#undef KTHOOK_DECLARE_RELAY_BODY

namespace kthook::arch::unsafe_relay {
template <typename HookPtrType, cconv Convention, typename Ret, typename Tuple>
struct relay_generator;

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, cconv::ccdecl, Ret, std::tuple<Args...>> {
  static Ret CCDECL relay(HookPtrType* this_hook, Args... args) {
    auto& cb = this_hook->get_callback();
    return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
  }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, cconv::cstdcall, Ret, std::tuple<Args...>> {
  static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
    auto& cb = this_hook->get_callback();
    return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
  }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, cconv::cthiscall, Ret, std::tuple<Args...>> {
  static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
    auto& cb = this_hook->get_callback();
    return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
  }
};

template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, cconv::cfastcall, Ret, std::tuple<Args...>> {
  // fastcall uses registers for first two integral/pointer types (left->right)
  // but stack is always used for aggregates
  // so we can use this trick to get outr hook object from stack
  struct fastcall_trick {
    HookPtrType* ptr;
  };

  static Ret CFASTCALL relay(fastcall_trick esp4, Args... args) {
    auto this_hook = esp4.ptr;
    auto& cb = this_hook->get_callback();
    return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
  }
};

#ifdef _MSC_VER
template <typename HookPtrType, typename Ret, typename... Args>
struct relay_generator<HookPtrType, cconv::cvectorcall, Ret, std::tuple<Args...>> {
  // vectorcall uses registers for first fp/integral types (left->right)
  // but stack is always used for aggregates
  // so we can use this trick to get our hook object from stack
  struct vectorcall_trick {
    HookPtrType* ptr;
  };

  static Ret CVECTORCALL relay(vectorcall_trick esp4, Args... args) {
    auto this_hook = esp4.ptr;
    auto& cb = this_hook->get_callback();
    return common_relay<decltype(cb), HookPtrType, Ret, Args...>(cb, this_hook, args...);
  }
};
#endif // #ifdef _MSC_VER
} // namespace kthook
#endif // #ifndef KTHOOK_RELAY_GENERATORS_HPP_
