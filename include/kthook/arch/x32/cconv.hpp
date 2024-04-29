#ifndef KTHOOK_ARCH_X86_CCONV_HPP_
#define KTHOOK_ARCH_X86_CCONV_HPP_

namespace kthook::arch {
enum class cconv {
  ccdecl,
  cfastcall,
  cthiscall,
  cstdcall,
  cvectorcall,
};
}
#endif