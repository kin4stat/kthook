#ifndef KTHOOK_DISASM_X86_HDE_HPP_
#define KTHOOK_DISASM_X86_HDE_HPP_

#undef hde_disasm
#define hde_disasm(code, hs) hde32_disasm(code, hs)
namespace kthook::disasm {
using hde = hde32s;
}

#endif // KTHOOK_DISASM_X86_HDE_HPP_