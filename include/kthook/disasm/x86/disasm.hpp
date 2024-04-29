#ifndef KTHOOK_DISASM_X86_DISASM_HPP_
#define KTHOOK_DISASM_X86_DISASM_HPP_

namespace kthook::disasm {
/**
 * Calculates count of bytes, that should be overwritten(granular in size of opcodes)
 * @param addr address
 * @return count of bytes that hook should overwrite
 */
inline std::size_t detect_hook_size(std::uintptr_t addr) {
  size_t size = 0;
  while (size < 5) {
    hde op;
    hde_disasm(reinterpret_cast<void*>(addr), &op);
    size += op.len;
    addr += op.len;
  }
  return size;
}
}

#endif // KTHOOK_DISASM_X86_DISASM_HPP_