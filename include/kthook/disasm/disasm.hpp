#ifndef KTHOOK_DISASM_DISASM_HPP_
#define KTHOOK_DISASM_DISASM_HPP_

#if defined(KTHOOK_32)
#include "x86/hde.hpp"
#include "x86/disasm.hpp"
#elif defined(KTHOOK_64)
#include "x64/hde.hpp"
#include "x86/disasm.hpp"
#endif

#endif // KTHOOK_DISASM_DISASM_HPP_