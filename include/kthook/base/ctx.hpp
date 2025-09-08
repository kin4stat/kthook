#ifndef KTHOOK_BASE_CTX_HPP_
#define KTHOOK_BASE_CTX_HPP_

namespace kthook::utils {
inline thread_local void* hook_ctx{};

inline void CCDECL save_ctx(void* ptr) {
  hook_ctx = ptr;
}

template <typename T>
inline T* CCDECL get_ctx() {
  return static_cast<T*>(hook_ctx);
}

template <bool Enable, typename T>
struct dependent_stack_holder {
  T ctx_storage_;

  using type = T;
  static constexpr bool is_stack = false;
};

template <typename T>
struct dependent_stack_holder<true, T> {
  std::stack<T> ctx_storage_;

  using type = T;
  static constexpr bool is_stack = true;
};

template <typename T>
typename T::type get_frame_ctx_storage(T* stack_holder) {
  if constexpr(T::is_stack) {
    return stack_holder.ctx_storage_.top();
  }
  else {
    return stack_holder.ctx_storage_;
  }
}
}

#endif // KTHOOK_BASE_CTX_HPP_