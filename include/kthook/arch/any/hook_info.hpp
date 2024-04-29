#ifndef KTHOOK_ARCH_ANY_HOOK_INFO_DECL_HPP_
#define KTHOOK_ARCH_ANY_HOOK_INFO_DECL_HPP_

namespace kthook::arch {
/**
 * struct for storing original bytes and hook destination
 */
struct hook_info {
  union {
    std::uintptr_t hook_address;
    void* hook_address_ptr;
  };

  std::unique_ptr<unsigned char[]> original_code;

  hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c)
    : hook_address(a),
      original_code(std::move(c)) {
  }

  hook_info(std::uintptr_t a)
    : hook_address(a),
      original_code(nullptr) {
  }
};
}

#endif // KTHOOK_ARCH_ANY_HOOK_INFO_DECL_HPP_