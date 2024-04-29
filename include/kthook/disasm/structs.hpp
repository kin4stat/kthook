#ifndef KTHOOK_DISASM_STRUCTS_HPP_
#define KTHOOK_DISASM_STRUCTS_HPP_

#if defined(KTHOOK_32)
#include "x86/structs.hpp"
#elif defined(KTHOOK_64)
#include "x64/structs.hpp"
#endif

#endif // KTHOOK_DISASM_STRUCTS_HPP_