#ifndef KTHOOK_XBYAK_WRAPPER_JMP_ALLOCATOR_HPP_
#define KTHOOK_XBYAK_WRAPPER_JMP_ALLOCATOR_HPP_

namespace kthook::xbyak_wrap {
inline struct JumpAllocator : Xbyak::Allocator {
  uint8_t* alloc(size_t size) override {
    void* ptr = Xbyak::AlignedMalloc(size, Xbyak::inner::ALIGN_PAGE_SIZE);
    platform::set_memory_prot(ptr, size, platform::MemoryProt::PROTECT_RWE);
    return reinterpret_cast<uint8_t*>(ptr);
  }

  void free(uint8_t* p) override {
  }

  bool useProtect() const override { return false; }
} default_jmp_allocator;

inline std::unique_ptr<Xbyak::CodeGenerator> get_jmp_generator() {
  return std::make_unique<Xbyak::CodeGenerator>(Xbyak::DEFAULT_MAX_CODE_SIZE, nullptr,
                                                &xbyak_wrap::default_jmp_allocator);
}
}
#endif // KTHOOK_XBYAK_WRAPPER_JMP_ALLOCATOR_HPP_