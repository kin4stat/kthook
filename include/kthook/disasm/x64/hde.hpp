#ifndef KTHOOK_DISASM_X64_HDE_HPP_
#define KTHOOK_DISASM_X64_HDE_HPP_

#undef hde_disasm
#define hde_disasm(code, hs) hde64_disasm(code, hs)
namespace kthook::disasm {
using hde = hde64s;
}

#endif // KTHOOK_DISASM_X64_HDE_HPP_