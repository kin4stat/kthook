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
};

template <typename T>
struct dependent_stack_holder<true, T> {
  std::stack<T> ctx_storage_stack;
};
}

#endif // KTHOOK_BASE_CTX_HPP_