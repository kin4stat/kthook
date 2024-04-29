#ifndef KTHOOK_HOOK_INTERFACE_HPP_
#define KTHOOK_HOOK_INTERFACE_HPP_

#define CONCAT(A, B) A ## B

#define DEFINE_CTX_STRUCT(name)\
  template<bool v>                                                            \
  struct storage_##name {                                                     \
    storage_##name() = default;                                               \
    storage_##name(const storage_##name&) noexcept = default;                 \
    storage_##name& operator=(storage_##name&&) noexcept = default;           \
    storage_##name& operator=(const storage_##name&) noexcept = default;      \
    ~storage_##name() = default;                                              \
  };                                                                          \
  template<>                                                                  \
  struct storage_##name<true> {                                               \
    storage_##name() = default;                                               \
    storage_##name(const storage_##name&) noexcept = default;                 \
    storage_##name(storage_##name&&) noexcept = default;                      \
    storage_##name& operator=(storage_##name&&) noexcept = default;           \
    storage_##name& operator=(const storage_##name&) noexcept = default;      \
    ~storage_##name() = default;                                              \
    name* _##name = nullptr;                                                  \
  };

#define DEFINE_CTX_GETTER(name, getter_name)                                                                \
  DEFINE_CTX_STRUCT(name)                                                                                   \
  template<bool enable/*, bool mutable_ctx*/>                                                               \
  struct name##_##getter_name : protected storage_##name<false> {                                           \
    name##_##getter_name() noexcept = default;                                                              \
    name##_##getter_name(const storage_##name& p) noexcept : storage_##name<false>(p) {}                    \
    name##_##getter_name(storage_##name&& p) noexcept : storage_##name<false>(std::move(p)) {}              \
    /*name##_##getter_name& operator=(name##_##getter_name&& p) noexcept = default*/                            \
    /*name##_##getter_name& operator=(const name##_##getter_name& p) noexcept = default*/                       \
    /*~name##_##getter_name() = default*/                                                                       \
  };                                                                                                        \
                                                                                                            \
  template</*bool mutable_ctx*/>                                                                            \
  struct name##_##getter_name<true/*, mutable_ctx*/> : protected storage_##name<true> {                     \
    name##_##getter_name() noexcept = default;                                                              \
    name##_##getter_name(const storage_##name& p) noexcept : storage_##name<true>(p) {}                     \
    name##_##getter_name(storage_##name&& p) noexcept : storage_##name<true>(std::move(p)) {}               \
    /*name##_##getter_name& operator=(name##_##getter_name&& p) noexcept = default*/                            \
    /*name##_##getter_name& operator=(const name##_##getter_name& p) noexcept = default*/                       \
    /*~name##_##getter_name() = default*/                                                                       \
    /*template<bool Cond = mutable_ctx, typename = std::enable_if_t<Cond>>*/                                \
    /*[[nodiscard]] name& getter_name() {*/                                                                 \
    /*  return *this->_##name;*/                                                                            \
    /*}*/                                                                                                   \
                                                                                                            \
    /*template<bool Cond = mutable_ctx>*/                                                                   \
    [[nodiscard]] const name& getter_name() const {                                                         \
      return *this->_##name;                                                                                \
    }                                                                                                       \
  };

namespace kthook::detail {
DEFINE_CTX_GETTER(cpu_ctx_int, int_regs);

DEFINE_CTX_GETTER(cpu_ctx_flags, cpu_flags);

DEFINE_CTX_GETTER(cpu_ctx_x87, fpu_state);

DEFINE_CTX_GETTER(cpu_ctx_segment_regs, segment_regs);

template <bool Enable>
struct ctx_save_storage {
  std::shared_ptr<std::uintptr_t> _storage0 = std::make_shared<std::uintptr_t>(0);
};

template <>
struct ctx_save_storage<true> {
  std::shared_ptr<std::uintptr_t> _storage0 = std::make_shared<std::uintptr_t>(0);
  std::shared_ptr<std::uintptr_t> _storage1 = std::make_shared<std::uintptr_t>(0);
};

template <typename HookTraits>
struct ctx_storage
    : cpu_ctx_int_int_regs<HookTraits::save_regs>,
      cpu_ctx_flags_cpu_flags<HookTraits::save_flags>,
      cpu_ctx_x87_fpu_state<HookTraits::save_x87>,
      cpu_ctx_segment_regs_segment_regs<HookTraits::save_segment_regs>,
      ctx_save_storage<HookTraits::save_regs ||
                       HookTraits::save_flags ||
                       HookTraits::save_x87 ||
                       HookTraits::save_segment_regs> {
  ctx_storage() noexcept = default;
  ctx_storage(const ctx_storage& other) = default;
  ctx_storage(ctx_storage&& other) noexcept = default;
  ctx_storage& operator=(const ctx_storage& other) noexcept = default;
  ctx_storage& operator=(ctx_storage&& other) noexcept = default;
  ~ctx_storage() = default;

  template <typename FuncSig, template<typename> typename Traits>
  friend class hook;

  template<typename T, typename StorageT>
  friend T* get_storage(StorageT& v);
protected:
  std::uintptr_t last_return_address{0};
};

template <typename T, typename StorageT>
inline T* get_storage(StorageT& v) {
  return &static_cast<T&>(v);
}
} // namespace kthook::detail

namespace kthook {
template <typename FuncSig, template<typename U> typename Traits, typename Discarded, typename Range>
struct hook_interface
    : detail::ctx_storage<Traits<FuncSig>> {
  using HookTraits = Traits<FuncSig>;
  using FunctionSignature = FuncSig;

  hook_interface(hook<FuncSig, Traits>* this_hook,
                 detail::ctx_storage<Traits<FuncSig>>& storage,
                 detail::discarded_holder<Discarded> d)
    : detail::ctx_storage<Traits<FuncSig>>(storage),
      this_hook(this_hook),
      d(d) {
  }

  static hook_interface create(hook<FuncSig, Traits>* this_hook,
                               detail::ctx_storage<HookTraits>& ctx_storage,
                               detail::discarded_holder<Discarded> d) {
    return hook_interface{this_hook, ctx_storage, d};
  }

  std::uintptr_t return_address() const noexcept {
    return this->last_return_address;
  }

  kthook_error_code_t install();
  kthook_error_code_t remove();

  typename HookTraits::hook_ret_t call_trampoline();

  hook<FuncSig, Traits>* this_hook;
  detail::discarded_holder<Discarded> d;
  using range = Range;
};
} // namespace kthook

#endif // #ifndef KTHOOK_HOOK_INTERFACE_HPP_
