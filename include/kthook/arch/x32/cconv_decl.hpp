#ifndef KTHOOK_X86_CCONV_DECL_HPP_
#define KTHOOK_X86_CCONV_DECL_HPP_

#undef CCDECL
#undef CFASTCALL
#undef CSTDCALL
#undef CTHISCALL
#undef CVECTORCALL

#ifdef __GNUC__
#define CCDECL __attribute__((cdecl))
#define CFASTCALL __attribute__((fastcall))
#define CSTDCALL __attribute__((stdcall))
#define CTHISCALL __attribute__((thiscall))
#else // ifdef __GNUC__
#define CVECTORCALL __vectorcall
#define CCDECL __cdecl
#define CFASTCALL __fastcall
#define CSTDCALL __stdcall
#define CTHISCALL __thiscall
#endif  // #ifdef __GNUC__

#endif // KTHOOK_X86_CCONV_DECL_HPP_